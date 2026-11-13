"""Structured diagnostics and request-scope state for the auth gate."""

import asyncio
import json
import logging
import time

import pytest

from ccdb_mcp.auth import AuthRejected, Authenticator, CCDBAuthMiddleware
from ccdb_mcp.config import Config

SECRET = "test-hmac-secret"


def _api_token(sub: str = "alice", *, groups=None) -> str:
    import base64
    import hashlib
    import hmac

    claims = {
        "sub": sub,
        "svc": "ccdb",
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
        "jti": "jti-1",
    }
    if groups is not None:
        claims["groups"] = groups
    payload = (
        base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    )
    mac = base64.urlsafe_b64encode(
        hmac.new(
            SECRET.encode(), f"fmcpv1:{payload}".encode(), hashlib.sha256
        ).digest()
    ).rstrip(b"=").decode()
    return f"fmcpv1.{payload}.{mac}"


class _Recorder:
    def __init__(self) -> None:
        self.messages: list[dict] = []
        self.state: dict = {}

    async def receive(self):
        return {"type": "http.request", "body": b"{}", "more_body": False}

    async def send(self, message):
        self.messages.append(message)

    async def app(self, scope, receive, send):
        self.state = scope.get("state", {})
        await send({
            "type": "http.response.start",
            "status": 200,
            "headers": [],
        })
        await send({
            "type": "http.response.body",
            "body": b"{}",
            "more_body": False,
        })

    @property
    def status(self) -> int:
        start = next(m for m in self.messages if m["type"] == "http.response.start")
        return start["status"]


def _call(headers: list[tuple[bytes, bytes]], *, method: str = "POST"):
    config = Config(
        token_hmac_secret=SECRET,
        dns_rebinding_protection=False,
    )
    recorder = _Recorder()
    middleware = CCDBAuthMiddleware(recorder.app, config=config)
    scope = {
        "type": "http",
        "method": method,
        "path": "/mcp",
        "headers": headers,
        "client": ("127.0.0.1", 54321),
        "state": {},
    }

    asyncio.run(middleware(scope, recorder.receive, recorder.send))
    return recorder


def _record(caplog) -> logging.LogRecord:
    for record in caplog.records:
        if record.getMessage() == "rejected request: invalid bearer token":
            return record
    raise AssertionError("no rejection was logged")


def test_malformed_api_token_logs_stable_reason(caplog):
    caplog.set_level(logging.WARNING, logger="ccdb_mcp.auth")
    recorder = _call([
        (b"authorization", b"Bearer fmcpv1.a.b.c"),
        (b"user-agent", b"pytest-agent"),
    ])
    assert recorder.status == 401
    record = _record(caplog)
    assert record.reason == "malformed_api_token_structure"
    assert record.token_kind == "api-token"
    assert record.binding == "absent"
    assert record.user_agent == "pytest-agent"
    assert "fmcpv1.a.b.c" not in caplog.text


def test_invalid_api_signature_logs_reason(caplog):
    caplog.set_level(logging.WARNING, logger="ccdb_mcp.auth")
    recorder = _call([
        (b"authorization", b"Bearer fmcpv1.payload.bad-signature"),
        (b"user-agent", b"pytest-agent"),
    ])
    assert recorder.status == 401
    record = _record(caplog)
    assert record.reason == "invalid_api_token"
    assert record.token_kind == "api-token"


def test_binding_presence_is_logged(caplog):
    caplog.set_level(logging.WARNING, logger="ccdb_mcp.auth")
    recorder = _call([
        (b"authorization", b"Bearer opaque-token"),
        (b"x-alliance-id-token", b"signed.id.token"),
        (b"user-agent", b"pytest-agent"),
    ])
    assert recorder.status == 401
    record = _record(caplog)
    assert record.reason == "no_token_validator"
    assert record.token_kind == "opaque"
    assert record.binding == "present"


def test_oversized_id_token_logged(caplog):
    caplog.set_level(logging.WARNING, logger="ccdb_mcp.auth")
    recorder = _call([
        (b"authorization", b"Bearer opaque-token"),
        (b"x-alliance-id-token", b"a" * (16 * 1024 + 1)),
        (b"user-agent", b"pytest-agent"),
    ])
    assert recorder.status == 401
    record = next(
        r for r in caplog.records
        if r.getMessage() == "rejected request: invalid alliance id token"
    )
    assert record.reason == "id_token_too_large"
    assert record.binding == "present"


def test_missing_token_logs_user_agent(caplog):
    caplog.set_level(logging.WARNING, logger="ccdb_mcp.auth")
    recorder = _call([(b"user-agent", b"pytest-agent")], method="GET")
    assert recorder.status == 401
    record = next(
        r for r in caplog.records
        if r.getMessage() == "rejected request: no bearer token"
    )
    assert record.reason == "missing_token"
    assert record.user_agent == "pytest-agent"


def test_malformed_fmcpv1_is_never_retried_as_oidc():
    config = Config(
        token_hmac_secret=SECRET,
        oidc_issuer_url="https://idp.example.invalid",
    )
    auth = Authenticator(config)
    seen: list[str] = []

    async def fake_validate(token, *, id_token=None):
        seen.append(token)
        raise AssertionError("OIDC must not be tried for an fmcpv1 token")

    auth.oidc.validate = fake_validate  # type: ignore[method-assign]
    try:
        with pytest.raises(AuthRejected) as exc:
            asyncio.run(auth.resolve("fmcpv1.a.b.c"))
        assert exc.value.reason == "malformed_api_token_structure"

        with pytest.raises(AuthRejected) as exc:
            asyncio.run(auth.resolve("fmcpv1.payload.bad-signature"))
        assert exc.value.reason == "invalid_api_token"
        assert seen == []
    finally:
        asyncio.run(auth.aclose())


def test_success_binds_user_and_method_into_scope():
    token = _api_token("alice")
    recorder = _call([
        (b"authorization", f"Bearer {token}".encode()),
        (b"user-agent", b"pytest-agent"),
    ])
    assert recorder.status == 200
    assert recorder.state["user"] == "alice"
    assert recorder.state["auth_method"] == "api-token"
    assert recorder.state["auth_bound"] is False
    assert recorder.state["is_staff"] is False
    assert recorder.state["sub"] == "alice"


def test_staff_api_token_binds_staff_flag():
    token = _api_token("alice", groups=["cc-staff"])
    recorder = _call([(b"authorization", f"Bearer {token}".encode())])
    assert recorder.status == 200
    assert recorder.state["is_staff"] is True
