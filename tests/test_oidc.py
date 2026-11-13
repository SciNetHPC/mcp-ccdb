"""Unit tests for OIDC validation, ID-token binding, and reason codes.

The first section covers ccdb's staff mapping: the Alliance IdP releases
staff membership as the `ccServiceAccess` attribute
(`cc_staff`/`co_staff`), not as a `groups` claim; `_groups_from` folds
those values into the `cc-staff` group that STAFF_GROUPS checks, so staff
is detected on the chatbot-forwarded OIDC path exactly as the token-issuer
stamps it into fmcpv1 tokens.  The rest covers the shared auth-boundary
hardening ported from alliance-docs-mcp.
"""

from __future__ import annotations

import base64
import time

import httpx2 as httpx
import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from ccdb_mcp.oidc import (
    OidcError,
    OidcUnavailableError,
    OidcValidator,
    _groups_from,
    is_structured_jwt,
)

# -- staff group mapping ---------------------------------------------------


def test_no_claims_yields_no_groups():
    assert _groups_from({}) == ()


def test_groups_claim_passes_through():
    assert _groups_from({"groups": ["cc-staff", "ras"]}) == ("cc-staff", "ras")


def test_groups_claim_string_form():
    assert _groups_from({"groups": "scinet"}) == ("scinet",)


def test_first_group_claim_wins():
    assert _groups_from({"groups": ["cc-staff"], "roles": ["x"]}) == ("cc-staff",)


def test_roles_claim_used_when_no_groups():
    assert _groups_from({"roles": ["ops"]}) == ("ops",)


def test_memberof_claim_used_when_no_groups_roles():
    assert _groups_from({"memberOf": ["ou=staff,dc=x"]}) == ("ou=staff,dc=x",)


def test_ccstaff_in_ccserviceaccess_marks_staff():
    assert _groups_from({"ccServiceAccess": ["cc_staff"]}) == ("cc-staff",)


def test_costaff_in_ccserviceaccess_marks_staff():
    assert _groups_from({"ccServiceAccess": ["co_staff", "trillium-access"]}) == (
        "cc-staff",
    )


def test_ccserviceaccess_without_staff_values_yields_no_group():
    assert _groups_from({"ccServiceAccess": ["cc_active_users", "trillium-access"]}) == ()


def test_string_ccserviceaccess_handled():
    assert _groups_from({"ccServiceAccess": "cc_staff"}) == ("cc-staff",)


def test_staff_values_case_insensitive():
    assert _groups_from({"ccServiceAccess": ["CC_STAFF"]}) == ("cc-staff",)


def test_real_groups_and_staff_access_compose():
    assert _groups_from({"groups": ["ras"], "ccServiceAccess": ["cc_staff"]}) == (
        "ras",
        "cc-staff",
    )


def test_staff_group_not_duplicated_when_both_sources_agree():
    assert _groups_from({"groups": ["cc-staff"], "ccServiceAccess": ["co_staff"]}) == (
        "cc-staff",
    )


# -- binding / reason-code suite (ported from alliance-docs-mcp) -----------

ISSUER = "https://idp.example.com"
AUDIENCE = "scinet_chatbot"
KID = "test-key-1"
JWKS_PATH = "/oidc/jwks"
USERINFO_PATH = "/oidc/userinfo"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _new_key() -> tuple[bytes, dict]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = private.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    numbers = private.public_key().public_numbers()
    n = _b64u(numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big"))
    e = _b64u(numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big"))
    return priv_pem, {
        "kty": "RSA",
        "kid": KID,
        "use": "sig",
        "alg": "RS256",
        "n": n,
        "e": e,
    }


PRIV_PEM, JWK = _new_key()

DISCOVERY = {
    "issuer": ISSUER,
    "jwks_uri": ISSUER + JWKS_PATH,
    "userinfo_endpoint": ISSUER + USERINFO_PATH,
}


def make_transport(*, userinfo_payload=None, userinfo_status=200):
    async def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            return httpx.Response(200, json=DISCOVERY)
        if path == JWKS_PATH:
            return httpx.Response(200, json={"keys": [JWK]})
        if path == USERINFO_PATH:
            if userinfo_status != 200:
                return httpx.Response(userinfo_status, json={"error": "invalid_token"})
            return httpx.Response(200, json=userinfo_payload or {})
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


def sign(payload: dict, *, key: bytes = PRIV_PEM) -> str:
    return pyjwt.encode(payload, key, algorithm="RS256", headers={"kid": KID})


def base_payload(**overrides) -> dict:
    payload = {
        "iss": ISSUER,
        "sub": "idp-sub",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    payload.update(overrides)
    return payload


def id_token(**overrides) -> str:
    payload = base_payload(aud=AUDIENCE)
    payload.update(overrides)
    return sign(payload)


def validator(
    *,
    audience=None,
    transport=None,
    require_bound_opaque=False,
    allow_jwt_access_tokens=False,
) -> OidcValidator:
    return OidcValidator(
        issuer=ISSUER,
        audience=audience,
        transport=transport or make_transport(),
        require_bound_opaque=require_bound_opaque,
        allow_jwt_access_tokens=allow_jwt_access_tokens,
    )


async def _reason(v: OidcValidator, token: str, **kwargs) -> str:
    try:
        await v.validate(token, **kwargs)
    except OidcError as exc:
        return exc.reason
    raise AssertionError("token was accepted")


def test_structured_jwt_detection():
    assert is_structured_jwt(id_token())
    assert not is_structured_jwt("opaque-token")
    assert not is_structured_jwt("a.b.c")
    assert not is_structured_jwt("a.b.c.d")


@pytest.mark.asyncio
async def test_jwt_access_token_rejected_by_default():
    v = validator(audience=AUDIENCE)
    try:
        assert (
            await _reason(v, id_token(preferred_username="alice", groups=["ras"]))
        ) == "jwt_access_token_not_accepted"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_jwt_access_token_accepted_only_when_enabled():
    v = validator(audience=AUDIENCE, allow_jwt_access_tokens=True)
    try:
        user = await v.validate(
            id_token(preferred_username="alice", groups=["ras"])
        )
    finally:
        await v.aclose()
    assert user.username == "alice"
    assert user.sub == "idp-sub"
    assert user.groups == ("ras",)


@pytest.mark.asyncio
async def test_jwt_access_token_wrong_audience_reason():
    v = validator(audience=AUDIENCE, allow_jwt_access_tokens=True)
    try:
        assert (
            await _reason(
                v,
                id_token(
                    aud="other-client",
                    preferred_username="alice",
                    groups=["ras"],
                ),
            )
        ) == "audience_mismatch"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_jwt_access_token_expired_reason():
    v = validator(audience=AUDIENCE, allow_jwt_access_tokens=True)
    try:
        assert (
            await _reason(
                v,
                id_token(
                    exp=int(time.time()) - 120,
                    preferred_username="alice",
                    groups=["ras"],
                ),
            )
        ) == "expired"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_opaque_token_resolved_via_userinfo():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(transport=transport)
    try:
        user = await v.validate("opaque-access-token")
    finally:
        await v.aclose()
    assert user.username == "alice"
    assert user.sub == "idp-sub"
    assert user.bound is False


@pytest.mark.asyncio
async def test_opaque_token_unbound_rejected_when_required():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(audience=AUDIENCE, transport=transport, require_bound_opaque=True)
    try:
        assert await _reason(v, "opaque-access-token") == "opaque_token_unbound"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_opaque_token_bound_with_matching_id_token():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(audience=AUDIENCE, transport=transport, require_bound_opaque=True)
    try:
        user = await v.validate(
            "opaque-access-token", id_token=id_token(preferred_username="alice")
        )
    finally:
        await v.aclose()
    assert user.username == "alice"
    assert user.sub == "idp-sub"
    assert user.bound is True


@pytest.mark.asyncio
async def test_opaque_token_binding_subject_mismatch():
    transport = make_transport(
        userinfo_payload={"sub": "somebody-else", "preferred_username": "alice"}
    )
    v = validator(audience=AUDIENCE, transport=transport)
    try:
        assert (
            await _reason(
                v, "opaque-access-token", id_token=id_token(sub="idp-sub")
            )
        ) == "binding_subject_mismatch"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_binding_requires_configured_audience():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(transport=transport)
    try:
        assert (
            await _reason(
                v, "opaque-access-token", id_token=id_token()
            )
        ) == "binding_audience_unconfigured"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_binding_rejects_wrong_id_token_audience():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(audience=AUDIENCE, transport=transport)
    try:
        assert (
            await _reason(
                v, "opaque-access-token", id_token=id_token(aud="other-client")
            )
        ) == "id_token_audience_mismatch"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_binding_rejects_wrong_id_token_issuer():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(audience=AUDIENCE, transport=transport)
    try:
        assert (
            await _reason(
                v,
                "opaque-access-token",
                id_token=id_token(iss="https://evil.example.com"),
            )
        ) == "id_token_issuer_mismatch"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_binding_rejects_expired_id_token():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(audience=AUDIENCE, transport=transport)
    try:
        assert (
            await _reason(
                v,
                "opaque-access-token",
                id_token=id_token(exp=int(time.time()) - 120),
            )
        ) == "id_token_expired"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_binding_rejects_unsigned_id_token():
    transport = make_transport(
        userinfo_payload={"sub": "idp-sub", "preferred_username": "alice"}
    )
    v = validator(audience=AUDIENCE, transport=transport)
    try:
        assert (
            await _reason(v, "opaque-access-token", id_token="opaque-id-token")
        ) == "invalid_id_token"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_opaque_userinfo_requires_subject():
    transport = make_transport(userinfo_payload={"preferred_username": "alice"})
    v = validator(transport=transport)
    try:
        assert (
            await _reason(v, "opaque-access-token")
        ) == "opaque_token_missing_subject"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_opaque_userinfo_requires_username():
    transport = make_transport(userinfo_payload={"sub": "idp-sub"})
    v = validator(transport=transport)
    try:
        assert (
            await _reason(v, "opaque-access-token")
        ) == "opaque_token_missing_username"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_opaque_token_rejected_when_userinfo_fails():
    transport = make_transport(userinfo_payload=None, userinfo_status=401)
    v = validator(transport=transport)
    try:
        assert (
            await _reason(v, "opaque-access-token")
        ) == "opaque_token_rejected"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_unreachable_issuer_raises_unavailable():
    async def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    v = validator(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(OidcUnavailableError) as exc:
            await v.validate("opaque-access-token")
        assert exc.value.reason == "issuer_unreachable"
    finally:
        await v.aclose()


@pytest.mark.asyncio
async def test_missing_token_reason():
    v = validator()
    try:
        assert await _reason(v, "") == "missing_token"
    finally:
        await v.aclose()
