"""End-to-end HTTP tests: auth gate, per-user scoping, OIDC + API tokens.

Spawns the real uvicorn app (like the other servers' HTTP tests) against a fake
Alliance Allocations API and, for the OIDC path, a fake IdP.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = REPO_ROOT / "src"
ACCEPT = "application/json, text/event-stream"

SECRET = "test-hmac-secret"
AUDIENCE = "scinet_chatbot"
KID = "test-key-1"


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


def _id_token(*, sub: str = "idp-sub", aud: str = AUDIENCE, **overrides) -> str:
    payload = {
        "iss": _FakeIdp.base_url,
        "sub": sub,
        "aud": aud,
        "iat": int(time.time()),
        "exp": int(time.time()) + 3600,
    }
    payload.update(overrides)
    return pyjwt.encode(
        payload, PRIV_PEM, algorithm="RS256", headers={"kid": KID}
    )


def _api_token(
    sub: str, *, svc: str = "ccdb", secret: str = SECRET, jti: str = "t1",
    exp: int | None = None, groups: list[str] | None = None,
) -> str:
    claims = {
        "sub": sub,
        "svc": svc,
        "iat": int(time.time()),
        "exp": exp if exp is not None else int(time.time()) + 86400,
        "jti": jti,
    }
    if groups is not None:
        claims["groups"] = groups
    payload = base64.urlsafe_b64encode(json.dumps(claims).encode()).rstrip(b"=").decode()
    mac = base64.urlsafe_b64encode(
        hmac.new(secret.encode(), f"fmcpv1:{payload}".encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    return f"fmcpv1.{payload}.{mac}"


# ----------------------------------------------------------------------
# Fake Alliance Allocations API (the CCDB backend)
# ----------------------------------------------------------------------

PERSON_ALICE = {
    "person": {
        "cci": "CCI-1", "username": "alice", "given_name": "Alice",
        "family_name": "Smith", "primary_email": "alice@example.ca",
        "language": "en",
        "raps": [{
            "rapi": "rrg-2030-00001",
            "groupname": "rrg-alice",
            "allocations": [{"alloc_id": "rrg-2030-00001-01"}],
        }],
    }
}

PERSON_BOB = {
    "person": {
        "cci": "CCI-2", "username": "bob", "given_name": "Bob",
        "family_name": "Jones", "primary_email": "bob@example.ca",
        "language": "fr",
        "raps": [{"rapi": "rrg-2030-99999"}],
    }
}

RAP_ALICE = {"rap": {"rapi": "rrg-2030-00001", "title": "Alice's RAP",
                     "owner": {"person": {"username": "alice"}}, "members": []}}
RAP_BOB = {"rap": {"rapi": "rrg-2030-99999", "title": "Bob's RAP",
                   "owner": {"person": {"username": "bob"}}, "members": []}}


class _FakeCcdbApi(BaseHTTPRequestHandler):
    calls: list[str] = []

    def log_message(self, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self.calls.append(self.path)
        if self.path == "/api/allocations/people/alice":
            self._json(PERSON_ALICE)
        elif self.path == "/api/allocations/people/bob":
            self._json(PERSON_BOB)
        elif self.path == "/api/allocations/raps/rrg-2030-00001":
            self._json(RAP_ALICE)
        elif self.path == "/api/allocations/raps/rrg-alice":
            self._json(RAP_ALICE)
        elif self.path == "/api/allocations/raps/rrg-2030-99999":
            self._json(RAP_BOB)
        else:
            self._json({"error": "not found"}, 404)


@pytest.fixture()
def ccdb_api():
    _FakeCcdbApi.calls = []
    base_url = ""

    def run():
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeCcdbApi)
        nonlocal base_url
        base_url = f"http://127.0.0.1:{server.server_address[1]}"
        server.serve_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    for _ in range(100):
        if base_url:
            break
        time.sleep(0.05)
    yield base_url
    _FakeCcdbApi.calls.clear()


# ----------------------------------------------------------------------
# Fake OIDC IdP (discovery + userinfo for opaque tokens)
# ----------------------------------------------------------------------

class _FakeIdp(BaseHTTPRequestHandler):
    base_url = ""

    def log_message(self, *args):
        pass

    def _json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.endswith("/.well-known/openid-configuration"):
            self._json({
                "issuer": _FakeIdp.base_url,
                "userinfo_endpoint": _FakeIdp.base_url + "/userinfo",
                "jwks_uri": _FakeIdp.base_url + "/jwks",
            })
        elif self.path.endswith("/userinfo"):
            auth = self.headers.get("authorization", "")
            if auth == "Bearer opaque-token":
                self._json({"sub": "idp-sub", "preferred_username": "alice"})
            else:
                self._json({"error": "invalid_token"}, 401)
        elif self.path.endswith("/jwks"):
            self._json({"keys": [JWK]})
        else:
            self._json({"error": "not found"}, 404)


@pytest.fixture()
def idp():
    base_url = ""

    def run():
        server = ThreadingHTTPServer(("127.0.0.1", 0), _FakeIdp)
        _FakeIdp.base_url = f"http://127.0.0.1:{server.server_address[1]}"
        nonlocal base_url
        base_url = _FakeIdp.base_url
        server.serve_forever()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    for _ in range(100):
        if base_url:
            break
        time.sleep(0.05)
    yield base_url


# ----------------------------------------------------------------------
# Spawn the real server
# ----------------------------------------------------------------------

def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


@pytest.fixture()
def spawn(tmp_path):
    proc = None

    def _spawn(ccdb_url: str | None, *, extra_env: dict | None = None) -> int:
        nonlocal proc
        port = _free_port()
        env = {
            **os.environ,
            "PYTHONPATH": str(SRC_DIR),
            "CCDB_MCP_HOST": "127.0.0.1",
            "CCDB_MCP_PORT": str(port),
            "CCDB_MCP_PATH": "/mcp",
            "DNS_REBINDING_PROTECTION": "true",
            **(extra_env or {}),
        }
        if ccdb_url:
            env["ALLOCATIONS_API_HOST"] = ccdb_url
            env["ALLOCATIONS_API_KEY"] = "fake-key"
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app:app",
             "--host", "127.0.0.1", "--port", str(port)],
            env=env,
            cwd=REPO_ROOT,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )
        _wait_health(f"http://127.0.0.1:{port}")
        return port

    yield _spawn
    if proc is not None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def _wait_health(url: str, timeout: float = 20.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=2) as res:
                if res.status == 200:
                    return
        except Exception:
            time.sleep(0.25)
    raise AssertionError("server did not become healthy")


def _post(port: int, body: dict, *, token: str | None = None,
          session_id: str | None = None, host: str | None = None,
          id_token: str | None = None):
    headers = {"content-type": "application/json", "accept": ACCEPT}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    if session_id is not None:
        headers["mcp-session-id"] = session_id
    if host is not None:
        headers["host"] = host
    if id_token is not None:
        headers["x-alliance-id-token"] = id_token
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp",
        data=json.dumps(body).encode(),
        headers=headers,
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as res:
            return (res.status, res.read().decode(),
                    res.info().get("mcp-session-id", ""))
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode(), ""


def _initialize(port: int, token: str | None, *, id_token: str | None = None):
    init = {
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "e2e", "version": "0"},
        },
    }
    return _post(port, init, token=token, id_token=id_token)


def _notify(port: int, session_id: str, token: str | None):
    return _post(port, {"jsonrpc": "2.0", "method": "notifications/initialized",
                        "params": {}}, token=token, session_id=session_id)


def _call(port: int, session_id: str, token: str, name: str, args: dict,
          *, id_token: str | None = None):
    return _post(port, {
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    }, token=token, session_id=session_id, id_token=id_token)


def _result(body: str) -> dict:
    """Extract the structured (or text) tool result from an SSE reply."""
    for line in body.splitlines():
        if not line.startswith("data: "):
            continue
        msg = json.loads(line[len("data: "):])
        res = msg.get("result") or {}
        sc = res.get("structuredContent")
        if sc is not None:
            return sc
        for c in res.get("content") or []:
            if c.get("text"):
                return json.loads(c["text"])
    return {}


# ----------------------------------------------------------------------
# Tests
# ----------------------------------------------------------------------

def test_health_and_root_are_public(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as res:
        assert res.status == 200
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=2) as res:
        assert res.status == 200


def test_metadata_anonymous_but_tools_require_token(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})

    status, _, session_id = _initialize(port, token=None)
    assert status == 200 and session_id

    status, body, _ = _post(port, {"jsonrpc": "2.0", "id": 4, "method": "tools/list",
                                   "params": {}}, token=None, session_id=session_id)
    assert status == 200
    assert "get_CCDB_allocations_from_username" in body

    status, body, _ = _call(port, session_id, token=None,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "alice"})
    assert status == 401


def test_invalid_tokens_rejected_at_gate(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    status, _, _ = _initialize(port, token="made-up-token")
    assert status == 401
    status, _, _ = _initialize(port, token=_api_token("alice", svc="other"))
    assert status == 401  # bound to a different service
    status, _, _ = _initialize(port, token=_api_token("alice", exp=int(time.time()) - 100_000))
    assert status == 401  # expired


def test_api_token_self_only_scoping(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice")
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "alice"})
    assert status == 200
    res = _result(body)
    assert res.get("username") == "alice"
    assert res.get("ok") is True
    assert "rrg-2030-00001" in json.dumps(res)

    # Asking for another user is denied, and the backend never sees the query.
    _FakeCcdbApi.calls.clear()
    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "bob"})
    assert status == 200
    res = _result(body)
    assert res.get("username") != "bob"
    assert res.get("ok") is False
    assert res.get("code") == "forbidden"
    assert "error" in res
    assert not any("people/bob" in c for c in _FakeCcdbApi.calls)


def test_username_input_is_trimmed(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice")
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    _FakeCcdbApi.calls.clear()
    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "  alice  "})
    assert status == 200
    res = _result(body)
    assert res.get("username") == "alice"
    assert res.get("ok") is True
    assert any(c == "/api/allocations/people/alice"
               for c in _FakeCcdbApi.calls)


def test_blank_username_is_invalid_argument_without_backend_call(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice")
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    _FakeCcdbApi.calls.clear()
    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "   \t "})
    assert status == 200
    res = _result(body)
    assert res.get("ok") is False
    assert res.get("code") == "invalid_argument"
    assert res.get("error")
    assert _FakeCcdbApi.calls == []


def test_missing_record_is_structured_not_found(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    # Staff may ask for a user with no record; the fake API answers 404.
    tok = _api_token("alice", groups=["cc-staff"])
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "carol"})
    assert status == 200
    res = _result(body)
    assert res.get("ok") is False
    assert res.get("code") == "not_found"
    assert res.get("error")


def test_rap_membership_enforced(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice")
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_resource_allocation_project_details_from_RAP",
                            args={"rap_id": "rrg-2030-00001"})
    assert status == 200 and "Alice's RAP" in body
    res = _result(body)
    assert res.get("ok") is True
    assert res.get("rapi") == "rrg-2030-00001"

    # Another user's RAP is denied without hitting the raps endpoint.
    _FakeCcdbApi.calls.clear()
    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_resource_allocation_project_details_from_RAP",
                            args={"rap_id": "rrg-2030-99999"})
    assert status == 200
    res = _result(body)
    assert "Bob's RAP" not in body
    assert res.get("ok") is False
    assert res.get("code") == "forbidden"
    assert not any("raps/rrg-2030-99999" in c for c in _FakeCcdbApi.calls)


def test_rap_id_is_trimmed_and_case_insensitive(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice")
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    _FakeCcdbApi.calls.clear()
    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_resource_allocation_project_details_from_RAP",
                            args={"rap_id": "  RRG-2030-00001  "})
    assert status == 200
    res = _result(body)
    assert res.get("ok") is True
    assert res.get("title") == "Alice's RAP"
    assert any(c == "/api/allocations/raps/rrg-2030-00001"
               for c in _FakeCcdbApi.calls)


def test_rap_groupname_and_alloc_id_aliases_are_member_scoped(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice")
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    # A group name and an alloc_id both resolve to the caller's RAP.
    for alias in ("RRG-ALICE", "rrg-2030-00001-01"):
        _FakeCcdbApi.calls.clear()
        status, body, _ = _call(
            port, session_id, tok,
            name="get_CCDB_resource_allocation_project_details_from_RAP",
            args={"rap_id": alias})
        assert status == 200
        res = _result(body)
        assert res.get("ok") is True, alias
        assert res.get("title") == "Alice's RAP", alias
        assert _FakeCcdbApi.calls, alias


def test_blank_rap_id_is_invalid_argument_without_backend_call(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice")
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    _FakeCcdbApi.calls.clear()
    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_resource_allocation_project_details_from_RAP",
                            args={"rap_id": "   "})
    assert status == 200
    res = _result(body)
    assert res.get("ok") is False
    assert res.get("code") == "invalid_argument"
    assert _FakeCcdbApi.calls == []


def test_revoked_token_rejected(ccdb_api, spawn, tmp_path):
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"issued": {}, "revokedJtis": ["tok-9"]}))
    port = spawn(ccdb_api, extra_env={
        "TOKEN_HMAC_SECRET": SECRET,
        "TOKEN_REVOCATION_PATH": str(store),
    })
    status, _, _ = _initialize(port, token=_api_token("alice", jti="tok-9"))
    assert status == 401
    status, _, _ = _initialize(port, token=_api_token("alice", jti="tok-10"))
    assert status == 200


def test_staff_groups_may_query_other_users(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    tok = _api_token("alice", groups=["cc-staff"])
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "bob"})
    assert status == 200
    assert _result(body).get("username") == "bob"

    # Staff may also look at a RAP they are not a member of.
    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_resource_allocation_project_details_from_RAP",
                            args={"rap_id": "rrg-2030-99999"})
    assert status == 200
    assert _result(body).get("title") == "Bob's RAP"


def test_staff_without_own_record_can_query_a_rap(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    # The fake backend has no /people/carol record; staff do not need one.
    tok = _api_token("carol", groups=["cc-staff"])
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_resource_allocation_project_details_from_RAP",
                            args={"rap_id": "rrg-2030-99999"})
    assert status == 200
    res = _result(body)
    assert res.get("ok") is True
    assert res.get("title") == "Bob's RAP"


def test_staff_groups_do_not_leak_to_non_staff(ccdb_api, spawn):
    port = spawn(ccdb_api, extra_env={"TOKEN_HMAC_SECRET": SECRET})
    # A non-staff group must not grant the exception.
    tok = _api_token("alice", groups=["ras"])
    status, _, session_id = _initialize(port, token=tok)
    assert status == 200 and session_id
    _notify(port, session_id, tok)

    status, body, _ = _call(port, session_id, tok,
                            name="get_CCDB_allocations_from_username",
                            args={"username": "bob"})
    assert status == 200
    assert "error" in _result(body)

    # Forged groups: tampering invalidates the HMAC and is rejected at the gate.
    p = _api_token("alice", groups=["ras"]).split(".")
    forged_claims = {
        "sub": "alice", "svc": "ccdb",
        "iat": int(time.time()), "exp": int(time.time()) + 86400,
        "jti": "t1", "groups": ["cc-staff"],
    }
    forged_payload = base64.urlsafe_b64encode(
        json.dumps(forged_claims).encode()
    ).rstrip(b"=").decode()
    forged = f"{p[0]}.{forged_payload}.{p[2]}"
    status, _, _ = _initialize(port, token=forged)
    assert status == 401


def test_oidc_opaque_token_scoped_to_preferred_username(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={"OIDC_ISSUER_URL": idp})
    status, _, session_id = _initialize(port, token="opaque-token")
    assert status == 200 and session_id
    _notify(port, session_id, "opaque-token")

    # Identity came from UserInfo: preferred_username=alice.
    status, body, _ = _call(port, session_id, "opaque-token",
                            name="get_CCDB_allocations_from_username",
                            args={"username": "alice"})
    assert status == 200
    assert _result(body).get("username") == "alice"

    # Cross-user still denied even with OIDC identity.
    status, body, _ = _call(port, session_id, "opaque-token",
                            name="get_CCDB_allocations_from_username",
                            args={"username": "bob"})
    assert status == 200
    assert _result(body).get("username") != "alice"
    assert "error" in _result(body)


def test_oidc_bound_opaque_token_allows_tool_calls(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={
        "OIDC_ISSUER_URL": idp,
        "OIDC_AUDIENCE": AUDIENCE,
    })
    status, _, session_id = _initialize(
        port, token="opaque-token", id_token=_id_token()
    )
    assert status == 200 and session_id
    _notify(port, session_id, "opaque-token")

    status, body, _ = _call(
        port, session_id, "opaque-token",
        name="get_CCDB_allocations_from_username",
        args={"username": "alice"}, id_token=_id_token(),
    )
    assert status == 200
    assert _result(body).get("username") == "alice"


def test_oidc_binding_subject_mismatch_rejected(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={
        "OIDC_ISSUER_URL": idp,
        "OIDC_AUDIENCE": AUDIENCE,
    })
    status, _, _ = _initialize(
        port, token="opaque-token", id_token=_id_token(sub="somebody-else")
    )
    assert status == 401


def test_oidc_binding_audience_mismatch_rejected(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={
        "OIDC_ISSUER_URL": idp,
        "OIDC_AUDIENCE": AUDIENCE,
    })
    status, _, _ = _initialize(
        port, token="opaque-token", id_token=_id_token(aud="other-client")
    )
    assert status == 401


def test_oidc_require_bound_opaque(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={
        "OIDC_ISSUER_URL": idp,
        "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_REQUIRE_BOUND_OPAQUE": "true",
    })
    status, _, _ = _initialize(port, token="opaque-token")
    assert status == 401  # rollout switch: no ID-token binding

    status, _, _ = _initialize(
        port, token="opaque-token", id_token=_id_token()
    )
    assert status == 200


def test_oidc_jwt_bearer_token_rejected_by_default(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={
        "OIDC_ISSUER_URL": idp,
        "OIDC_AUDIENCE": AUDIENCE,
    })
    # A validly signed ID token is not an access token, even though it would
    # resolve to a username on the JWT path.
    status, _, _ = _initialize(
        port, token=_id_token(preferred_username="alice", groups=["ras"])
    )
    assert status == 401


def test_oidc_jwt_bearer_token_opt_in(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={
        "OIDC_ISSUER_URL": idp,
        "OIDC_AUDIENCE": AUDIENCE,
        "OIDC_ALLOW_JWT_ACCESS_TOKENS": "true",
    })
    status, _, _ = _initialize(
        port, token=_id_token(preferred_username="alice", groups=["ras"])
    )
    assert status == 200


def test_malformed_api_token_not_retried_as_oidc(ccdb_api, spawn, idp):
    port = spawn(ccdb_api, extra_env={
        "TOKEN_HMAC_SECRET": SECRET,
        "OIDC_ISSUER_URL": idp,
        "OIDC_AUDIENCE": AUDIENCE,
    })
    for bad in ("fmcpv1.zzz", "fmcpv1.a.b.c", "fmcpv1." + "x" * 5000 + ".y"):
        status, _, _ = _initialize(port, token=bad)
        assert status == 401, bad


def test_host_header_guard(ccdb_api, spawn):
    # ALLOWED_HOSTS only permits evil.example, so real 127.0.0.1 requests are 403.
    port = spawn(ccdb_api, extra_env={
        "TOKEN_HMAC_SECRET": SECRET,
        "ALLOWED_HOSTS": "evil.example:*",
    })
    status, _, _ = _initialize(port, token=_api_token("alice"))
    assert status == 403
    # ... except the public health path, which bypasses the guard.
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=2) as res:
        assert res.status == 200
