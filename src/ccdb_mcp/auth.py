"""Bearer-token authentication for the public CCDB MCP server.

Decision order per request:

* Public paths (health/root) pass through untouched.
* A request without a bearer token is admitted only for the JSON-RPC
  metadata methods (``initialize``, ``notifications/initialized``,
  ``tools/list``); anything else is rejected with 401.
* Otherwise the bearer token is verified as an fmcpv1 API token (local
  HMAC + revocation list) when it carries the ``fmcpv1.`` marker; a
  malformed API token is rejected on that path and never retried as OIDC.
  Every other token is validated as an OIDC access token (RS256 JWT only
  when explicitly enabled, or UserInfo for opaque tokens).  A
  userinfo/issuer outage reads as a 502 (upstream failure), never as an
  invalid credential.
* Opaque access tokens do not expose their audience.  When a front end
  forwards its signed ID token in ``X-Alliance-ID-Token``, that token's
  audience and subject are verified against the access token's UserInfo
  subject; ``OIDC_REQUIRE_BOUND_OPAQUE`` makes the binding mandatory.
* Rejections carry a stable reason code plus token-kind/binding/User-Agent
  fields for structured logs -- never the token itself.
* On success the resolved username plus the staff decision are bound into
  the request scope, where the tool handlers read the username as the
  subject for every CCDB lookup.

Also enforces the DNS-rebinding host-header guard when
``DNS_REBINDING_PROTECTION`` is on (public paths exempt).
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Optional

from starlette.types import ASGIApp, Receive, Scope, Send

from ccdb_mcp.api_token import ApiTokenAuth, ApiTokenError, TOKEN_VERSION
from ccdb_mcp.config import Config
from ccdb_mcp.oidc import (
    OidcError,
    OidcUnavailableError,
    OidcValidator,
    is_structured_jwt,
)
from ccdb_mcp.staff import StaffEvaluator

log = logging.getLogger(__name__)

# JSON-RPC methods a client is allowed to call without any credential.
_ANONYMOUS_METHODS = frozenset({"initialize", "notifications/initialized", "tools/list"})

# A signed ID token is a few KB.  Reject anything absurd without parsing it;
# the header is attacker-controlled even before the access token is checked.
_MAX_ID_TOKEN_BYTES = 16 * 1024

# Header through which the chatbot forwards the signed ID token from the same
# login, used to bind an otherwise audience-less opaque access token.
ID_TOKEN_HEADER = b"x-alliance-id-token"


class AuthRejected(Exception):
    """A credential was presented but rejected.

    ``reason`` is a stable, low-cardinality code safe for structured logs;
    it never contains the token or any other secret.
    """

    def __init__(self, reason: str, message: str = "") -> None:
        super().__init__(message or reason)
        self.reason = reason


@dataclass(frozen=True)
class ResolvedUser:
    username: str
    groups: tuple[str, ...]
    method: str
    sub: Optional[str] = None
    bound: bool = False
    is_staff: bool = False


def token_kind(token: str) -> str:
    """Classify a bearer token for diagnostics without trusting its claims."""
    if token.startswith(TOKEN_VERSION + "."):
        return "api-token"
    if is_structured_jwt(token):
        return "jwt"
    return "opaque"


def binding_state(id_token: Optional[str]) -> str:
    return "present" if id_token else "absent"


class Authenticator:
    """Validates bearer tokens (API token first, then OIDC) to a username.

    Identity plus group memberships, plus the staff decision, come back
    together so the middleware can bind them once per request.
    """

    def __init__(self, config: Config) -> None:
        self.api_tokens = (
            ApiTokenAuth(
                secret=config.token_hmac_secret,
                service_id=config.service_id,
                revocation_path=config.token_revocation_path,
            )
            if config.api_token_enabled
            else None
        )
        self.oidc = (
            OidcValidator(
                issuer=config.oidc_issuer_url,
                audience=config.oidc_audience,
                require_bound_opaque=config.oidc_require_bound_opaque,
                allow_jwt_access_tokens=config.oidc_allow_jwt_access_tokens,
            )
            if config.oidc_enabled
            else None
        )
        self.staff = StaffEvaluator(
            staff_groups=config.staff_groups,
            staff_list_path=config.staff_list_path,
        )

    async def resolve(
        self, token: str, *, id_token: Optional[str] = None
    ) -> ResolvedUser:
        """Resolve *token* to a user or raise :class:`AuthRejected`.

        An ``fmcpv1.*`` token is handled exclusively on the API-token path:
        a malformed one is rejected, never retried as OIDC.  Raises
        :class:`OidcUnavailableError` when the issuer cannot be reached
        (callers should report 502, not 401).
        """
        if token.startswith(TOKEN_VERSION + "."):
            if self.api_tokens is None:
                raise AuthRejected("api_token_disabled")
            try:
                verified = self.api_tokens.verify(token)
            except ApiTokenError as exc:
                raise AuthRejected(exc.reason) from exc
            if verified is None:
                raise AuthRejected("invalid_api_token")
            return ResolvedUser(
                username=verified.sub,
                groups=verified.groups,
                method="api-token",
                sub=verified.sub,
                is_staff=self.staff.is_staff(verified.sub, verified.groups),
            )

        if self.oidc is None:
            raise AuthRejected("no_token_validator")

        try:
            user = await self.oidc.validate(token, id_token=id_token)
        except OidcUnavailableError:
            raise
        except OidcError as exc:
            raise AuthRejected(exc.reason) from exc
        return ResolvedUser(
            username=user.username,
            groups=user.groups,
            method="oidc",
            sub=user.sub,
            bound=user.bound,
            is_staff=self.staff.is_staff(user.username, user.groups),
        )

    async def aclose(self) -> None:
        if self.api_tokens is not None:
            self.api_tokens.close()
        if self.oidc is not None:
            await self.oidc.aclose()
        self.staff.close()


async def _read_body(receive: Receive) -> bytes:
    body = b""
    more = True
    while more:
        message = await receive()
        body += message.get("body", b"")
        more = message.get("more_body", False)
    return body


def _replay_after(receive: Receive, body: bytes) -> Receive:
    sent = False

    async def wrapper():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        return await receive()

    return wrapper


def _jsonrpc_method(body: bytes) -> str:
    """Extract the JSON-RPC method name from a request body, or '' if unparseable."""
    try:
        request = json.loads(body.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return ""
    if isinstance(request, dict):
        return str(request.get("method", ""))
    return ""


def _split_host(host: str) -> tuple[str, Optional[str]]:
    """Split a Host header (or allow-list entry) into (address, port)."""
    host = host.strip().lower()
    if not host:
        return "", None
    if host.startswith("["):  # IPv6 literal, e.g. [::1]:443
        close = host.find("]")
        if close == -1:
            return host, None
        rest = host[close + 1:]
        port = rest[1:] if rest.startswith(":") else None
        return host[1:close], port
    if host.count(":") == 1:
        address, _, port = host.rpartition(":")
        return address, port
    return host, None


def _host_allowed(host_header: str, allowed_hosts: tuple[str, ...]) -> bool:
    address, port = _split_host(host_header)
    for entry in allowed_hosts:
        e_address, e_port = _split_host(entry)
        if e_address != "*" and e_address != address:
            continue
        if e_port is None or e_port == "*":
            return True
        if e_port == port:
            return True
    return False


class CCDBAuthMiddleware:
    """ASGI middleware enforcing bearer-token auth + the Host-header guard."""

    def __init__(self, app: ASGIApp, *, config: Config) -> None:
        self.app = app
        self.config = config
        self.authenticator = Authenticator(config)
        self.public_paths = frozenset({config.health_path, "/"})
        self.mcp_path = config.path

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in self.public_paths:
            await self.app(scope, receive, send)
            return

        if self.config.dns_rebinding_protection:
            hosts = {k.lower(): v for k, v in scope["headers"]}
            host = (hosts.get(b"host") or b"").decode("latin-1")
            if not _host_allowed(host, self.config.allowed_hosts):
                log.warning(
                    "rejected request: unexpected host header",
                    extra={"client": _client(scope), "host": host},
                )
                await _json_response(send, 403, {"error": "forbidden host"})
                return

        headers = {k.lower(): v for k, v in scope["headers"]}
        user_agent = (headers.get(b"user-agent") or b"").decode("latin-1")
        raw = headers.get(b"authorization")
        token = None
        if raw:
            text = raw.decode("latin-1")
            if text.startswith("Bearer "):
                token = text[len("Bearer "):].strip()

        if not token:
            if scope.get("method") == "POST":
                body = await _read_body(receive)
                method = _jsonrpc_method(body)
                if method in _ANONYMOUS_METHODS:
                    await self.app(scope, _replay_after(receive, body), send)
                    return
                log.warning(
                    "rejected request: no bearer token",
                    extra={
                        "client": _client(scope),
                        "method": method,
                        "reason": "missing_token",
                        "user_agent": user_agent,
                    },
                )
            else:
                log.warning(
                    "rejected request: no bearer token",
                    extra={
                        "client": _client(scope),
                        "method": "",
                        "reason": "missing_token",
                        "user_agent": user_agent,
                    },
                )
            await _json_response(
                send, 401, {"error": "missing bearer token"},
                extra_headers=[(b"www-authenticate", b'Bearer realm="mcp"')],
            )
            return

        id_token: Optional[str] = None
        raw_id_token = headers.get(ID_TOKEN_HEADER)
        if raw_id_token:
            id_token = raw_id_token.decode("latin-1").strip() or None
        if id_token is not None and len(id_token.encode("latin-1")) > _MAX_ID_TOKEN_BYTES:
            log.warning(
                "rejected request: invalid alliance id token",
                extra={
                    "client": _client(scope),
                    "reason": "id_token_too_large",
                    "token_kind": token_kind(token),
                    "binding": binding_state(id_token),
                    "user_agent": user_agent,
                },
            )
            await _json_response(
                send, 401, {"error": "invalid bearer token"},
                extra_headers=[(b"www-authenticate", b'Bearer realm="mcp"')],
            )
            return

        try:
            user = await self.authenticator.resolve(token, id_token=id_token)
        except OidcUnavailableError as exc:
            log.warning(
                "auth service unavailable",
                extra={
                    "client": _client(scope),
                    "reason": exc.reason,
                    "token_kind": token_kind(token),
                    "binding": binding_state(id_token),
                    "user_agent": user_agent,
                },
            )
            await _json_response(send, 502, {"error": "auth_service_unavailable"})
            return
        except AuthRejected as exc:
            log.warning(
                "rejected request: invalid bearer token",
                extra={
                    "client": _client(scope),
                    "reason": exc.reason,
                    "token_kind": token_kind(token),
                    "binding": binding_state(id_token),
                    "user_agent": user_agent,
                },
            )
            await _json_response(
                send, 401, {"error": "invalid bearer token"},
                extra_headers=[(b"www-authenticate", b'Bearer realm="mcp"')],
            )
            return

        scope.setdefault("state", {})
        scope["state"]["user"] = user.username
        scope["state"]["groups"] = user.groups
        scope["state"]["auth_method"] = user.method
        scope["state"]["auth_bound"] = user.bound
        scope["state"]["is_staff"] = user.is_staff
        if user.sub is not None:
            scope["state"]["sub"] = user.sub
        await self.app(scope, receive, send)


async def _json_response(
    send: Send,
    status: int,
    payload: dict[str, Any],
    *,
    extra_headers: list[tuple[bytes, bytes]] | None = None,
) -> None:
    body = json.dumps(payload).encode("utf-8")
    headers = [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode()),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    await send({
        "type": "http.response.start",
        "status": status,
        "headers": headers,
    })
    await send({
        "type": "http.response.body",
        "body": body,
        "more_body": False,
    })


def _client(scope: Scope) -> str:
    client = scope.get("client") or ("", 0)
    return f"{client[0]}:{client[1]}"
