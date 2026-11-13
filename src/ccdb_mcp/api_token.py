from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import time
from dataclasses import dataclass
from pathlib import Path

log = logging.getLogger(__name__)

# Self-contained, HMAC-signed per-user API tokens issued by the token-issuer
# web application (see the token-issuer project). Format:
#
#   fmcpv1.<base64url(claims-json)>.<base64url(hmac)>
#
#   claims = {"sub","svc","iat","exp","jti"}
#   hmac   = HMAC-SHA256(TOKEN_HMAC_SECRET, "fmcpv1:" + payload)
#
# The issuer and this server share TOKEN_HMAC_SECRET (from a secret manager).
# Each token is bound to one user (sub) and one server (svc); revocation is
# by jti against the issuer's shared JSON store.

TOKEN_VERSION = "fmcpv1"

# Grace period for clock skew between the issuer and this server.
_LEEWAY_SECONDS = 5 * 60
# Defence against absurdly large signatures/payloads in the auth header.
_MAX_PAYLOAD_BYTES = 4096
_MAX_SIGNATURE_BYTES = 128


class ApiTokenError(Exception):
    """Raised when a token carries the ``fmcpv1.`` marker but cannot be
    parsed as an API token (never for a merely invalid credential -- those
    return None).

    ``reason`` is a stable, low-cardinality code for structured auth logs.
    Callers must not fall through to OIDC after this is raised: the token
    claimed to be an API token and must be rejected on that path.
    """

    def __init__(self, message: str, *, reason: str = "malformed_api_token") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass(frozen=True)
class ApiToken:
    sub: str
    svc: str
    iat: int
    exp: int
    jti: str
    groups: tuple[str, ...] = ()


def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64u_decode(data: str) -> bytes:
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))


def _mac(payload: str, secret: str) -> str:
    digest = hmac.new(
        secret.encode("utf-8"), b"fmcpv1:" + payload.encode("utf-8"), hashlib.sha256
    ).digest()
    return _b64u_encode(digest)


def _groups(claims: dict) -> tuple[str, ...]:
    raw = claims.get("groups")
    if isinstance(raw, list):
        return tuple(str(g) for g in raw if isinstance(g, str))
    return ()


def verify_api_token(
    token: str,
    *,
    service_id: str,
    secret: str,
    revoked: set[str] | frozenset[str] | None = None,
    blacklisted: set[str] | frozenset[str] | None = None,
    now: float | None = None,
) -> ApiToken | None:
    """Verify an fmcpv1 token.

    Returns the parsed token when it is authentic, bound to *service_id*,
    unexpired, not revoked, and not blacklisted; otherwise ``None``.
    """
    if not token.startswith(TOKEN_VERSION + "."):
        return None

    parts = token.split(".")
    if len(parts) != 3:
        raise ApiTokenError(
            "API token must have exactly three dot-separated parts",
            reason="malformed_api_token_structure",
        )
    _version, payload, signature = parts
    if not payload or not signature:
        raise ApiTokenError(
            "API token has an empty payload or signature",
            reason="malformed_api_token_structure",
        )
    if len(payload) > _MAX_PAYLOAD_BYTES or len(signature) > _MAX_SIGNATURE_BYTES:
        raise ApiTokenError(
            "API token payload or signature is too large",
            reason="malformed_api_token_size",
        )

    expected = _mac(payload, secret)
    if not hmac.compare_digest(expected, signature):
        # Authentic-looking structure, wrong credential.  Do not parse the
        # unverified payload and do not try OIDC: the fmcpv1 marker is
        # authoritative for how this token must be handled.
        return None

    try:
        claims = json.loads(_b64u_decode(payload).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ApiTokenError(
            f"malformed API token payload: {exc}",
            reason="malformed_api_token_payload",
        ) from exc
    if not isinstance(claims, dict):
        raise ApiTokenError(
            "API token payload is not a JSON object",
            reason="malformed_api_token_payload",
        )

    sub = claims.get("sub")
    svc = claims.get("svc")
    jti = claims.get("jti")
    if not all(isinstance(x, str) and x for x in (sub, svc, jti)):
        raise ApiTokenError(
            "API token is missing a non-empty sub, svc, or jti claim",
            reason="malformed_api_token_claims",
        )
    try:
        iat = int(claims["iat"])
        exp = int(claims["exp"])
    except (KeyError, TypeError, ValueError) as exc:
        raise ApiTokenError(
            "API token has an invalid iat or exp claim",
            reason="malformed_api_token_claims",
        ) from exc

    if svc != service_id:
        return None
    now_ts = int(now) if now is not None else int(time.time())
    if exp <= now_ts - _LEEWAY_SECONDS:
        return None
    if revoked and jti in revoked:
        return None
    if blacklisted and sub.casefold() in {u.casefold() for u in blacklisted}:
        return None

    return ApiToken(sub=sub, svc=svc, iat=iat, exp=exp, jti=jti, groups=_groups(claims))


class RevocationList:
    """Revoked-token ids, mirrored from the token-issuer's JSON store.

    The issuer persists ``{"issued": {...}, "revokedJtis": [...]}`` to a
    shared volume; this server mounts that volume read-only and re-reads it
    on a timer, so revocation takes effect within ``reload_seconds``.
    """

    def __init__(self, path: str | os.PathLike[str], *, reload_seconds: float = 15.0):
        self._path = Path(path)
        self._reload_seconds = reload_seconds
        self._mtime_ns: int | None = None
        self._last_check = 0.0
        self._loaded_once = False
        self._jtis: set[str] = set()
        self._blacklisted: set[str] = set()

    def jtis(self) -> set[str]:
        self._maybe_reload()
        return self._jtis

    def is_revoked(self, jti: str) -> bool:
        return jti in self.jtis()

    def blacklisted(self) -> set[str]:
        self._maybe_reload()
        return self._blacklisted

    def is_blacklisted(self, sub: str) -> bool:
        return sub.casefold() in self.blacklisted()

    def _maybe_reload(self) -> None:
        now = time.monotonic()
        if self._loaded_once and now - self._last_check < self._reload_seconds:
            return
        self._loaded_once = True
        self._last_check = now
        try:
            stat = self._path.stat()
        except OSError:
            self._jtis = set()
            self._blacklisted = set()
            return
        if stat.st_mtime_ns == self._mtime_ns:
            return
        self._mtime_ns = stat.st_mtime_ns
        try:
            data = json.loads(self._path.read_text("utf-8"))
        except (OSError, ValueError):
            return
        candidates: object = None
        if isinstance(data, dict):
            candidates = data.get("revokedJtis")
            if not isinstance(candidates, list):
                candidates = data.get("revoked")
        elif isinstance(data, list):
            candidates = data
        if isinstance(candidates, list):
            self._jtis = {str(j) for j in candidates if isinstance(j, (str, int))}
        bldata = data.get("blacklisted") if isinstance(data, dict) else None
        if isinstance(bldata, list):
            self._blacklisted = {
                str(u).casefold() for u in bldata if isinstance(u, str) and u
            }

    def close(self) -> None:
        self._jtis = set()
        self._blacklisted = set()


class ApiTokenAuth:
    """Verifies per-user API tokens and exposes the bound username.

    One instance per server, built from TOKEN_HMAC_SECRET/SERVICE_ID. Use it
    everywhere a bearer token could be an API token.
    """

    def __init__(
        self,
        *,
        secret: str,
        service_id: str,
        revocation_path: str | None = None,
        reload_seconds: float = 15.0,
    ):
        self._secret = secret
        self._service_id = service_id
        self._revocations = (
            RevocationList(revocation_path, reload_seconds=reload_seconds)
            if revocation_path
            else None
        )

    def verify(self, token: str) -> ApiToken | None:
        """Return the parsed token when valid for this server, else ``None``."""
        return verify_api_token(
            token,
            service_id=self._service_id,
            secret=self._secret,
            revoked=self._revocations.jtis() if self._revocations else None,
            blacklisted=self._revocations.blacklisted() if self._revocations else None,
        )

    def close(self) -> None:
        if self._revocations is not None:
            self._revocations.close()
