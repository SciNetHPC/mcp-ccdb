"""OIDC (Alliance IAM) access-token validation for the CCDB server.

The chatbot authenticates the user with OIDC and holds the user's access
token on its session; public clients carry fmcpv1 API tokens.  This server
only needs to *validate* access tokens -- it never obtains tokens, so no IdP
client registration is required: it relies on the IdP's public
discovery/JWKS/userinfo endpoints, which it reaches over a configurable
issuer URL.

Design notes:

* The token is verified as a signed RS256 JWT (issuer/expiry/optional
  audience/SHA-256 over the signing input) using the IdP's published JWKS;
  we never trust the chatbot's assertion alone.
* Opaque access tokens (not a 3-part JWT) are not blindly accepted:
  identity then comes from the IdP's UserInfo endpoint, which validates
  the token server-side and returns the canonical ``preferred_username``.
  A malformed or unverifiable *structured* JWT is rejected outright.
* The Alliance IdP issues opaque access tokens, and its UserInfo response
  does not expose the token's audience.  An opaque token is therefore
  accepted only with an optional signed ID-token binding (the chatbot,
  which is the registered RP, forwards its ID token alongside the access
  token).  Requiring ``require_bound_opaque`` makes the binding mandatory:
  the ID token must verify against the configured audience and its ``sub``
  must match the UserInfo ``sub``.  The ID token is never accepted as a
  bearer access token by itself.
* Discovery metadata, the key set and per-subject userinfo are cached with
  bounded TTLs so a burst of connections does not hammer the IdP.
* The username from the token/UserInfo is the cluster account name the
  CCDB lookups are scoped to.
"""

from __future__ import annotations

import base64
import json
import time
from typing import Optional

import httpx2 as httpx
import jwt
from jwt import ExpiredSignatureError, InvalidAudienceError, InvalidIssuerError
from jwt import InvalidTokenError
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

WELLKNOWN_PATH = "/.well-known/openid-configuration"

_GROUP_CLAIMS = ("groups", "roles", "memberOf")


class OidcError(Exception):
    """Raised when a token cannot be validated or no username results.

    ``reason`` is a stable, low-cardinality code for structured auth logs.
    It never contains the token or any other secret.
    """

    def __init__(
        self,
        message: str,
        *,
        reason: str = "invalid_token",
        upstream_status: Optional[int] = None,
    ) -> None:
        super().__init__(message)
        self.reason = reason
        self.upstream_status = upstream_status


class OidcUnavailableError(OidcError):
    """The issuer could not be reached (transport/DNS/timeout), as opposed to
    the token itself being rejected. Callers should treat this as an upstream
    service failure (e.g. HTTP 502), not as an invalid credential."""

    def __init__(self, message: str) -> None:
        super().__init__(message, reason="issuer_unreachable")


class OidcUser:
    def __init__(
        self,
        *,
        username: str,
        sub: Optional[str] = None,
        groups: tuple[str, ...] = (),
        bound: bool = False,
    ) -> None:
        self.username = username
        self.sub = sub
        self.groups = groups
        # True when an opaque access token was validated together with a
        # signed ID token whose subject it matched (see validate()).
        self.bound = bound


def _b64u_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _jwk_to_pem(jwk: dict) -> bytes:
    """Turn an RSA JWK (``n``/``e``) into a PEM public key for jwt.decode."""
    n = int.from_bytes(_b64u_decode(jwk["n"]), "big")
    e = int.from_bytes(_b64u_decode(jwk["e"]), "big")
    public_key = RSAPublicNumbers(e, n).public_key()
    return public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)


# The Alliance IdP releases no `groups`/`roles` claim (confirmed in the
# chatbot's `oidc userinfo received` logs); staff membership is released as
# the `ccServiceAccess` attribute instead (`cc_staff` / `co_staff` for
# staff -- verified against the CCDB LDAP).  Fold those into the
# "cc-staff" group so the staff check works for the OIDC-forwarded path
# and matches what the token-issuer stamps into fmcpv1 tokens.
_STAFF_ACCESS = frozenset({"cc_staff", "co_staff"})
_STAFF_GROUP = "cc-staff"


def _groups_from(obj: dict) -> tuple[str, ...]:
    groups: list[str] = []
    for key in _GROUP_CLAIMS:
        raw = obj.get(key)
        if isinstance(raw, list):
            groups += [str(g) for g in raw if isinstance(g, str) and g]
            break
        if isinstance(raw, str) and raw:
            groups.append(raw)
            break
    access = obj.get("ccServiceAccess")
    if isinstance(access, str):
        access = [access]
    if isinstance(access, list) and any(
        isinstance(v, str) and v.lower() in _STAFF_ACCESS for v in access
    ):
        if _STAFF_GROUP not in groups:
            groups.append(_STAFF_GROUP)
    return tuple(groups)


def is_structured_jwt(token: str) -> bool:
    """Return True when *token* looks like a three-part signed JWT.

    A token that has three parts and a decodable JSON header claiming an
    algorithm is treated as a JWT even if the rest is invalid.  It must
    never fall through to the opaque-token UserInfo path: a malformed JWT
    is a bad credential, not an opaque token.
    """
    parts = token.split(".")
    if len(parts) != 3 or not parts[0] or not parts[1] or not parts[2]:
        return False
    try:
        header = json.loads(_b64u_decode(parts[0]).decode("utf-8"))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(header, dict) and "alg" in header


def _jwt_reason(exc: InvalidTokenError, *, id_token: bool = False) -> str:
    prefix = "id_token_" if id_token else ""
    if isinstance(exc, ExpiredSignatureError):
        return prefix + "expired"
    if isinstance(exc, InvalidAudienceError):
        return prefix + "audience_mismatch"
    if isinstance(exc, InvalidIssuerError):
        return prefix + "issuer_mismatch"
    return "invalid_" + ("id_token" if id_token else "token")


class OidcValidator:
    """Validates OIDC access tokens against an issuer's discovery/JWKS/userinfo."""

    def __init__(
        self,
        *,
        issuer: str,
        audience: Optional[str] = None,
        transport: Optional[httpx.AsyncBaseTransport] = None,
        metadata_ttl: float = 600.0,
        jwks_ttl: float = 300.0,
        userinfo_ttl: float = 60.0,
        require_bound_opaque: bool = False,
        allow_jwt_access_tokens: bool = False,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.require_bound_opaque = require_bound_opaque
        self.allow_jwt_access_tokens = allow_jwt_access_tokens
        self._transport = transport
        self._ttl_metadata = metadata_ttl
        self._ttl_jwks = jwks_ttl
        self._ttl_userinfo = userinfo_ttl

        self._http: Optional[httpx.AsyncClient] = None
        self._metadata: Optional[dict] = None
        self._metadata_at = 0.0
        self._jwks: Optional[dict[str, dict]] = None
        self._jwks_at = 0.0
        self._userinfo: dict[str, tuple[float, str, tuple[str, ...]]] = {}

    # -- HTTP --------------------------------------------------------------

    async def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = httpx.AsyncClient(
                transport=self._transport,
                timeout=httpx.Timeout(10.0),
            )
        return self._http

    async def _get(
        self, url: str, *, headers: Optional[dict[str, str]] = None
    ) -> httpx.Response:
        """GET with transport failures normalized to :class:`OidcUnavailableError`.

        A token that is simply invalid yields a normal HTTP response (401/403
        from UserInfo) and is handled by the caller; only failures to even
        reach the issuer raise OidcUnavailableError.
        """
        try:
            response = await (await self._client()).get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise OidcUnavailableError(f"issuer unreachable: {exc}") from exc
        return response

    async def aclose(self) -> None:
        if self._http is not None:
            await self._http.aclose()
            self._http = None

    # -- IdP metadata / keys ----------------------------------------------

    async def _discover(self) -> dict:
        now = time.time()
        if self._metadata is not None and now - self._metadata_at < self._ttl_metadata:
            return self._metadata
        response = await self._get(f"{self.issuer}{WELLKNOWN_PATH}")
        if response.status_code != 200:
            raise OidcUnavailableError(
                f"OIDC discovery failed: HTTP {response.status_code}"
            )
        self._metadata = response.json()
        self._metadata_at = now
        return self._metadata

    async def _keyset(self, *, refresh: bool = False) -> dict[str, dict]:
        now = time.time()
        if not refresh and self._jwks is not None and now - self._jwks_at < self._ttl_jwks:
            return self._jwks
        jwks_uri = (await self._discover()).get("jwks_uri")
        if not jwks_uri:
            raise OidcError("issuer did not advertise a jwks_uri")
        response = await self._get(jwks_uri)
        if response.status_code != 200:
            raise OidcUnavailableError(f"JWKS fetch failed: HTTP {response.status_code}")
        keys = {
            key["kid"]: key
            for key in response.json().get("keys", [])
            if key.get("kid") and key.get("kty") == "RSA"
        }
        self._jwks = keys
        self._jwks_at = now
        return keys

    async def _public_key(self, kid: str) -> bytes:
        keys = await self._keyset()
        if kid not in keys:
            keys = await self._keyset(refresh=True)  # key rotation: refetch once
        if kid not in keys:
            raise OidcError(f"no matching signing key for kid {kid!r}")
        return _jwk_to_pem(keys[kid])

    # -- username + groups resolution --------------------------------------

    async def _identity(self, token: str, payload: dict) -> tuple[str, tuple[str, ...]]:
        sub = payload.get("sub")
        cached = self._userinfo.get(sub) if isinstance(sub, str) else None
        if cached is not None and cached[0] > time.time():
            return cached[1], cached[2]

        username: Optional[str] = payload.get("preferred_username") or payload.get(
            "username"
        )
        groups = _groups_from(payload)
        if not username or not groups:
            userinfo_endpoint = (await self._discover()).get("userinfo_endpoint")
            if not userinfo_endpoint:
                raise OidcError(
                    "issuer did not advertise a userinfo_endpoint",
                    reason="issuer_invalid_metadata",
                )
            response = await self._get(
                userinfo_endpoint, headers={"Authorization": f"Bearer {token}"}
            )
            if response.status_code != 200:
                raise OidcError(
                    f"UserInfo failed: HTTP {response.status_code}",
                    reason="userinfo_rejected",
                    upstream_status=response.status_code,
                )
            userinfo = response.json()
            userinfo_sub = userinfo.get("sub")
            if isinstance(sub, str) and isinstance(userinfo_sub, str) and userinfo_sub != sub:
                raise OidcError(
                    "UserInfo subject does not match the token subject",
                    reason="userinfo_subject_mismatch",
                )
            username = username or userinfo.get("preferred_username") or userinfo.get(
                "username"
            )
            groups = groups or _groups_from(userinfo)

        if not username:
            raise OidcError(
                "could not determine a username from the token",
                reason="missing_username",
            )

        if isinstance(sub, str):
            self._userinfo[sub] = (time.time() + self._ttl_userinfo, username, groups)
        return username, groups

    # -- main entry --------------------------------------------------------

    async def validate(
        self, token: str, *, id_token: Optional[str] = None
    ) -> OidcUser:
        """Validate *token* and return the user it represents.

        For an opaque access token, *id_token* is an optional signed ID
        token from the same login.  When supplied, its audience is verified
        and its subject must equal the UserInfo subject.  The ID token is
        never accepted as an access token on its own.

        Raises :class:`OidcError` with a stable ``reason`` on any failure.
        """
        if not token:
            raise OidcError("missing bearer token", reason="missing_token")

        if is_structured_jwt(token):
            if not self.allow_jwt_access_tokens:
                # The Alliance IdP issues opaque access tokens.  A JWT here
                # is an ID token, not an access token; accepting it would
                # bypass the opaque-token binding below.
                raise OidcError(
                    "JWT access tokens are not accepted",
                    reason="jwt_access_token_not_accepted",
                )
            return await self._validate_jwt_access(token)

        # Opaque token: identity can only come from UserInfo, which
        # validates the token server-side. Do not attempt any claim parsing
        # on an unverified token.
        if self.require_bound_opaque and id_token is None:
            raise OidcError(
                "opaque access token is not bound to an ID token",
                reason="opaque_token_unbound",
            )

        expected_sub: Optional[str] = None
        bound = False
        if id_token is not None:
            binding = await self.validate_id_token(id_token)
            expected_sub = binding.sub
            bound = True

        user = await self._userinfo_for_opaque(token, expected_sub=expected_sub)
        return OidcUser(
            username=user.username,
            sub=user.sub,
            groups=user.groups,
            bound=bound,
        )

    async def _validate_jwt_access(self, token: str) -> OidcUser:
        """Validate a JWT access token (only when explicitly enabled)."""
        header = self._header(token)
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise OidcError(
                "token uses an unsupported signing scheme",
                reason="unsupported_signing_scheme",
            )

        pem = await self._public_key(header["kid"])
        options = {"require": ["exp", "iss", "sub"]}
        try:
            payload = jwt.decode(
                token,
                pem,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options=options,
                leeway=30,
            )
        except InvalidTokenError as exc:
            raise OidcError(
                f"invalid token: {exc}", reason=_jwt_reason(exc)
            ) from exc

        username, groups = await self._identity(token, payload)
        return OidcUser(username=username, sub=payload.get("sub"), groups=groups)

    async def validate_id_token(self, token: str) -> OidcUser:
        """Validate a signed ID token used as an audience binding.

        Requires ``OIDC_AUDIENCE`` so the ``aud`` check is meaningful, and
        returns the ``sub`` that the opaque access token's UserInfo subject
        must match.  This method does not consult UserInfo.
        """
        if not self.audience:
            raise OidcError(
                "OIDC_AUDIENCE is required for ID-token binding",
                reason="binding_audience_unconfigured",
            )
        if not is_structured_jwt(token):
            raise OidcError(
                "ID token is not a structured JWT", reason="invalid_id_token"
            )
        header = self._header(token)
        if header.get("alg") != "RS256" or not header.get("kid"):
            raise OidcError(
                "ID token uses an unsupported signing scheme",
                reason="invalid_id_token",
            )

        pem = await self._public_key(header["kid"])
        options = {"require": ["exp", "iat", "iss", "sub", "aud"]}
        try:
            payload = jwt.decode(
                token,
                pem,
                algorithms=["RS256"],
                issuer=self.issuer,
                audience=self.audience,
                options=options,
                leeway=30,
            )
        except InvalidTokenError as exc:
            raise OidcError(
                f"invalid ID token: {exc}",
                reason=_jwt_reason(exc, id_token=True),
            ) from exc

        sub = payload.get("sub")
        if not isinstance(sub, str) or not sub:
            raise OidcError(
                "ID token has no subject", reason="id_token_missing_subject"
            )
        return OidcUser(
            username=payload.get("preferred_username")
            or payload.get("username")
            or "",
            sub=sub,
            groups=_groups_from(payload),
            bound=True,
        )

    async def _userinfo_for_opaque(
        self, token: str, *, expected_sub: Optional[str] = None
    ) -> OidcUser:
        userinfo_endpoint = (await self._discover()).get("userinfo_endpoint")
        if not userinfo_endpoint:
            raise OidcError(
                "issuer did not advertise a userinfo_endpoint",
                reason="issuer_invalid_metadata",
            )
        response = await self._get(
            userinfo_endpoint, headers={"Authorization": f"Bearer {token}"}
        )
        if response.status_code != 200:
            raise OidcError(
                f"token rejected by UserInfo: HTTP {response.status_code}",
                reason="opaque_token_rejected",
                upstream_status=response.status_code,
            )
        userinfo = response.json()
        sub = userinfo.get("sub")
        if not isinstance(sub, str) or not sub:
            raise OidcError(
                "UserInfo did not include a subject",
                reason="opaque_token_missing_subject",
            )
        if expected_sub is not None and sub != expected_sub:
            raise OidcError(
                "ID token subject does not match the access token",
                reason="binding_subject_mismatch",
            )
        username = userinfo.get("preferred_username") or userinfo.get("username")
        if not username:
            raise OidcError(
                "UserInfo did not include a username",
                reason="opaque_token_missing_username",
            )
        return OidcUser(
            username=username,
            sub=sub,
            groups=_groups_from(userinfo),
            bound=expected_sub is not None,
        )

    @staticmethod
    def _header(token: str) -> dict:
        parts = token.split(".")
        try:
            header = json.loads(_b64u_decode(parts[0]).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OidcError(
                "malformed token header", reason="malformed_token"
            ) from exc
        if not isinstance(header, dict):
            raise OidcError("malformed token header", reason="malformed_token")
        return header
