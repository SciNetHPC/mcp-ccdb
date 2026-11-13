from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Mapping


def _env_int(env: Mapping[str, str], name: str, default: int) -> int:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        raise ValueError(f"{name} must be an integer, got {raw!r}")


def _env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    raw = env.get(name, "").strip().lower()
    if not raw:
        return default
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"{name} must be a boolean, got {raw!r}")


def _env_list(env: Mapping[str, str], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = env.get(name, "").strip()
    if not raw:
        return default
    return tuple(part.strip() for part in raw.split(",") if part.strip())


@dataclass(frozen=True)
class Config:
    """Runtime configuration for the CCDB MCP server.

    Auth combines OIDC access tokens (validated against the issuer's
    JWKS/userinfo, for a trusted front end that forwards each user's token)
    with per-user fmcpv1 API tokens (verified with the shared HMAC secret,
    for public MCP clients).  Non-staff callers are scoped to their own
    data; staff may query other users.
    """

    # CCDB / Allocations API backend (the server's own privileged credentials).
    api_host: str | None = None
    allocations_api_key: str | None = None

    # HTTP transport.
    host: str = "0.0.0.0"
    port: int = 8081
    path: str = "/mcp"
    health_path: str = "/health"
    debug: bool = False

    # OIDC validation of access tokens issued for the chatbot client.
    oidc_issuer_url: str | None = None
    oidc_audience: str | None = None

    # Some IdPs issue opaque access tokens whose UserInfo response does not
    # expose the token's audience.  A trusted front end (the registered RP)
    # can forward its signed ID token in X-Alliance-ID-Token so this server
    # can verify the login's audience and subject.  Keep the requirement off
    # while older front ends still omit the header.
    oidc_require_bound_opaque: bool = False
    # The IdP does not issue JWT access tokens.  A JWT presented as a bearer
    # token is an ID token and must not be accepted as an access token; the
    # switch exists only for IdPs that genuinely issue RS256 access tokens.
    oidc_allow_jwt_access_tokens: bool = False

    # Per-user API tokens (self-contained fmcpv1.* strings issued by the
    # token-issuer web app and verified against the shared HMAC secret).
    token_hmac_secret: str | None = None
    service_id: str = "ccdb"
    token_revocation_path: str | None = None

    # Staff membership: a user may query records other than their own when
    # their groups intersect STAFF_GROUPS (from the OIDC token/UserInfo or
    # the fmcpv1 "groups" claim) or their username is on the staff list
    # file on the shared token-issuer volume.
    staff_groups: tuple[str, ...] = ("cc-staff", "scinet")
    staff_list_path: str | None = None

    # Transport security: DNS-rebinding / host-header gate.  ALLOWED_HOSTS
    # replaces the localhost defaults when set (see the public job file).
    allowed_hosts: tuple[str, ...] = ("127.0.0.1:*", "localhost:*", "[::1]:*")
    allowed_origins: tuple[str, ...] = ()
    dns_rebinding_protection: bool = True

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.oidc_issuer_url)

    @property
    def api_token_enabled(self) -> bool:
        return bool(self.token_hmac_secret)

    @property
    def auth_enabled(self) -> bool:
        return self.oidc_enabled or self.api_token_enabled

    @property
    def backend_enabled(self) -> bool:
        return bool(self.api_host and self.allocations_api_key)

    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None) -> "Config":
        env = os.environ if env is None else env
        return cls(
            api_host=env.get("ALLOCATIONS_API_HOST") or None,
            allocations_api_key=env.get("ALLOCATIONS_API_KEY") or None,
            host=env.get("CCDB_MCP_HOST", "0.0.0.0"),
            port=_env_int(env, "CCDB_MCP_PORT", 8081),
            path=env.get("CCDB_MCP_PATH", env.get("MCP_PATH", "/mcp")),
            health_path=env.get("HEALTH_PATH", "/health"),
            debug=_env_bool(env, "DEBUG", False),
            oidc_issuer_url=env.get("OIDC_ISSUER_URL") or None,
            oidc_audience=env.get("OIDC_AUDIENCE") or None,
            oidc_require_bound_opaque=_env_bool(
                env, "OIDC_REQUIRE_BOUND_OPAQUE", False
            ),
            oidc_allow_jwt_access_tokens=_env_bool(
                env, "OIDC_ALLOW_JWT_ACCESS_TOKENS", False
            ),
            token_hmac_secret=env.get("TOKEN_HMAC_SECRET") or None,
            service_id=env.get("SERVICE_ID", "ccdb"),
            token_revocation_path=env.get("TOKEN_REVOCATION_PATH") or None,
            staff_groups=_env_list(
                env, "STAFF_GROUPS", ("cc-staff", "scinet")
            ),
            staff_list_path=env.get("STAFF_LIST_PATH") or None,
            allowed_hosts=_env_list(
                env, "ALLOWED_HOSTS", ("127.0.0.1:*", "localhost:*", "[::1]:*")
            ),
            allowed_origins=_env_list(env, "ALLOWED_ORIGINS", ()),
            dns_rebinding_protection=_env_bool(env, "DNS_REBINDING_PROTECTION", True),
        )
