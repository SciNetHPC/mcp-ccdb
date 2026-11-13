"""Unit tests for fmcpv1 API-token verification."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import pytest

from ccdb_mcp.api_token import (
    ApiTokenAuth,
    ApiTokenError,
    RevocationList,
    verify_api_token,
)

SECRET = "test-hmac-secret"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _sign(payload: str, secret: str = SECRET) -> str:
    mac = hmac.new(
        secret.encode(), f"fmcpv1:{payload}".encode(), hashlib.sha256
    ).digest()
    return _b64u(mac)


def _api_token(
    sub: str,
    *,
    svc: str = "filemcp",
    secret: str = SECRET,
    jti: str = "t1",
    exp: int | None = None,
) -> str:
    claims = {
        "sub": sub,
        "svc": svc,
        "iat": int(time.time()),
        "exp": exp if exp is not None else int(time.time()) + 86400,
        "jti": jti,
    }
    payload = _b64u(json.dumps(claims).encode())
    return f"fmcpv1.{payload}.{_sign(payload, secret)}"


def test_round_trip():
    tok = _api_token("alice", svc="filemcp")
    v = verify_api_token(tok, service_id="filemcp", secret=SECRET)
    assert v and v.sub == "alice" and v.svc == "filemcp" and v.jti == "t1"


def test_wrong_service_rejected():
    tok = _api_token("alice", svc="filemcp")
    assert verify_api_token(tok, service_id="ccdb", secret=SECRET) is None


def test_wrong_secret_rejected():
    tok = _api_token("alice", svc="filemcp")
    assert verify_api_token(tok, service_id="filemcp", secret="other-secret") is None


def test_tampered_payload_rejected():
    tok = _api_token("alice", svc="filemcp")
    parts = tok.split(".")
    forged = _b64u(json.dumps({"sub": "mallory", "svc": "filemcp",
                               "iat": 1, "exp": int(time.time()) + 86400, "jti": "x"}).encode())
    assert verify_api_token(f"{parts[0]}.{forged}.{parts[2]}",
                            service_id="filemcp", secret=SECRET) is None


def test_expired_rejected():
    tok = _api_token("alice", svc="filemcp", exp=int(time.time()) - 1000)
    assert verify_api_token(tok, service_id="filemcp", secret=SECRET) is None


def test_revoked_jti_rejected():
    tok = _api_token("alice", svc="filemcp", jti="revoked-1")
    assert verify_api_token(tok, service_id="filemcp", secret=SECRET,
                            revoked={"revoked-1"}) is None
    assert verify_api_token(tok, service_id="filemcp", secret=SECRET,
                            revoked={"other"}) is not None


def test_blacklisted_user_rejected():
    tok = _api_token("alice", svc="filemcp")
    assert verify_api_token(tok, service_id="filemcp", secret=SECRET) is not None
    # Blacklist match is case-insensitive (the store is lowercased).
    assert verify_api_token(tok, service_id="filemcp", secret=SECRET,
                            blacklisted={"alice"}) is None
    assert verify_api_token(tok, service_id="filemcp", secret=SECRET,
                            blacklisted={"ALICE"}) is None
    assert verify_api_token(_api_token("bob", svc="filemcp"), service_id="filemcp",
                            secret=SECRET, blacklisted={"alice"}) is not None


def test_revocation_list_parses_blacklist(tmp_path):
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"issued": {}, "revokedJtis": [],
                                 "blacklisted": ["alice", "BOB"]}))
    rl = RevocationList(store, reload_seconds=0.01)
    try:
        assert rl.blacklisted() == {"alice", "bob"}  # lowercased
        assert rl.is_blacklisted("alice")
        assert rl.is_blacklisted("ALICE")
        assert not rl.is_blacklisted("mallory")
    finally:
        rl.close()


def test_garbage_rejected():
    assert verify_api_token("fmcpv1.abc.def", service_id="filemcp", secret=SECRET) is None
    assert verify_api_token("not-a-token", service_id="filemcp", secret=SECRET) is None


def test_verify_uses_service_id():
    auth = ApiTokenAuth(secret=SECRET, service_id="filemcp")
    assert auth.verify(_api_token("bob", svc="filemcp")).sub == "bob"
    assert auth.verify(_api_token("bob", svc="other")) is None
    assert auth.verify("garbage") is None


def test_revocation_list_reloads_on_mtime(tmp_path):
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"issued": {}, "revokedJtis": ["jti-1"]}))
    rl = RevocationList(store, reload_seconds=0.01)
    try:
        assert rl.is_revoked("jti-1")
        assert not rl.is_revoked("jti-2")
        store.write_text(json.dumps({"issued": {}, "revokedJtis": ["jti-1", "jti-2"]}))
        import os
        os.utime(store)
        for _ in range(50):
            if rl.is_revoked("jti-2"):
                break
            time.sleep(0.01)
        assert rl.is_revoked("jti-2")
    finally:
        rl.close()


def test_revocation_list_missing_file_empty(tmp_path):
    rl = RevocationList(tmp_path / "nope.json")
    assert rl.jtis() == set()
    rl.close()


@pytest.mark.parametrize("tok", ["", "fmcpv1", "not-a-token"])
def test_unmarked_tokens_are_not_api_tokens(tok):
    assert verify_api_token(tok, service_id="filemcp", secret=SECRET) is None


@pytest.mark.parametrize("tok", ["fmcpv1.a", "fmcpv1.a.b.c.d", "fmcpv1..sig"])
def test_malformed_structure_has_reason(tok):
    with pytest.raises(ApiTokenError) as exc:
        verify_api_token(tok, service_id="filemcp", secret=SECRET)
    assert exc.value.reason == "malformed_api_token_structure"


def test_oversized_token_has_reason():
    tok = f"fmcpv1.{'a' * 4097}.{'b' * 10}"
    with pytest.raises(ApiTokenError) as exc:
        verify_api_token(tok, service_id="filemcp", secret=SECRET)
    assert exc.value.reason == "malformed_api_token_size"


def test_unparseable_signed_payload_has_reason():
    payload = _b64u(b"this is not json")
    tok = f"fmcpv1.{payload}.{_sign(payload)}"
    with pytest.raises(ApiTokenError) as exc:
        verify_api_token(tok, service_id="filemcp", secret=SECRET)
    assert exc.value.reason == "malformed_api_token_payload"


def test_missing_claims_has_reason():
    payload = _b64u(json.dumps({"sub": "alice", "svc": "filemcp"}).encode())
    tok = f"fmcpv1.{payload}.{_sign(payload)}"
    with pytest.raises(ApiTokenError) as exc:
        verify_api_token(tok, service_id="filemcp", secret=SECRET)
    assert exc.value.reason == "malformed_api_token_claims"


def test_invalid_timestamps_have_reason():
    payload = _b64u(json.dumps({
        "sub": "alice", "svc": "filemcp", "jti": "t1",
        "iat": "not-a-number", "exp": int(time.time()) + 60,
    }).encode())
    tok = f"fmcpv1.{payload}.{_sign(payload)}"
    with pytest.raises(ApiTokenError) as exc:
        verify_api_token(tok, service_id="filemcp", secret=SECRET)
    assert exc.value.reason == "malformed_api_token_claims"
