# ccdb-mcp

Model Context Protocol server for **CCDB**, the allocations and accounts
database used by the Digital Research Alliance of Canada. It exposes two
read-only tools and applies the caller's identity to every lookup, so a user
sees their own allocation records and nothing else.

The software is written and maintained by **SciNet HPC Consortium**. It is
published so that other Alliance sites — and anyone else with a compatible
CCDB or allocations API — can run their own instance.

## Tools

| Tool | Arguments | Returns |
|---|---|---|
| `get_CCDB_allocations_from_username` | `username` | A person's CCDB record, including their resource allocation projects (RAPs), identifiers, and profile fields |
| `get_CCDB_resource_allocation_project_details_from_RAP` | `rap_id` | One RAP: title, group name, allocations, owner and members |

Both tools declare an output schema and return structured content on failure
as well as success, so a typed client can branch on `ok`, `code` and `error`
instead of parsing prose:

```json
{"ok": false, "code": "forbidden", "error": "you may only access CCDB records for yourself"}
```

`code` is one of `invalid_argument`, `not_found`, or `forbidden`.

For non-staff callers, RAP identifiers match case-insensitively and accept
the RAP id (`rrg-2030-00000`), its group name, or one of its allocation ids;
a sub-allocation id (`rrg-2030-00000-01`) resolves to its parent RAP. Every
alias must belong to one of the caller's own RAPs.

## Contents

- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Authentication and authorization](#authentication-and-authorization)
- [Configuration](#configuration)
- [Staff (cross-user) access](#staff-cross-user-access)
- [Output schema and CCDB quirks](#output-schema-and-ccdb-quirks)
- [Development](#development)
- [Deployment](#deployment)
- [Security](#security)
- [Contributing](#contributing)
- [Licence](#licence)

## Requirements

- Python 3.11 or newer.
- An upstream CCDB / allocations API and an API key for it.
- **At least one** authentication method. The process refuses to build a
  serving app with neither: an unauthenticated CCDB endpoint would expose
  every user's records.

There is no database. The server is stateless apart from two optional
read-only files (the token revocation list and the staff list).

## Quick start

```sh
cp .env.example .env      # fill in the backend and auth values
uv sync --extra test
uv run --no-sync pytest -q
uv run --no-sync ccdb-mcp # http://localhost:8081/mcp
```

`uv` is the reference tooling. A plain virtual environment works too:

```sh
python -m venv .venv
. .venv/bin/activate
pip install -e '.[test]'
pytest -q
python -m ccdb_mcp.server
```

`GET /health` returns `CCDB MCP server ok`; `GET /` returns a short status
line. Both are unauthenticated on purpose, for platform probes.

## Authentication and authorization

Every request to the MCP path is authenticated except the JSON-RPC metadata
methods (`initialize`, `notifications/initialized`, `tools/list`). Those are
allowed without a credential so a client can discover the tools; calling
either tool still requires a valid token.

Two credentials are accepted:

1. **OIDC access token** — the normal case for a chat front end that forwards
   each user's token. Opaque tokens are validated through the issuer's
   UserInfo endpoint; RS256 JWT access tokens are accepted only when
   `OIDC_ALLOW_JWT_ACCESS_TOKENS=true`, because an ID token presented as an
   access token must not be accepted. An issuer or UserInfo outage returns
   `502`, never `401`.

   Opaque tokens do not expose their audience. If the front end also forwards
   the signed ID token from the same login in `X-Alliance-ID-Token`, the
   server checks that token's audience and subject against the access token's
   UserInfo subject. Set `OIDC_REQUIRE_BOUND_OPAQUE=true` to make that binding
   mandatory.

2. **fmcpv1 API token** — a self-contained, HMAC-signed token minted by a
   token-issuer deployment, for public MCP clients that cannot carry an OIDC
   access token. The server verifies the signature locally, requires `svc` to
   equal `SERVICE_ID`, checks `exp`, and consults the shared revocation list
   for `jti` and username blocks. A token that carries the `fmcpv1.` marker is
   never retried as OIDC.

Either way the middleware resolves a username and a group list and binds them
into the request scope. The tools read the bound username rather than trusting
a tool argument, so identity cannot be smuggled in through the request body.

Authorization rules:

- A non-staff caller may query **only their own** record and **only RAPs they
  are a member of**. A cross-user request is refused before the upstream API
  is called.
- Staff may query any user and any RAP. See below.

## Configuration

Copy `.env.example` to `.env` for local runs. In production, inject values
from a secret manager.

| Variable | Meaning |
|---|---|
| `ALLOCATIONS_API_HOST` | Base URL of the CCDB / allocations API |
| `ALLOCATIONS_API_KEY` | The server's own API key for that backend |
| `CCDB_MCP_HOST` | Listen address (default `0.0.0.0`) |
| `CCDB_MCP_PORT` | Listen port (default `8081`) |
| `CCDB_MCP_PATH` | MCP endpoint path (default `/mcp`; `MCP_PATH` also accepted) |
| `HEALTH_PATH` | Health endpoint (default `/health`) |
| `DEBUG` | Parsed but currently unused |
| `OIDC_ISSUER_URL` | OIDC issuer; enables OIDC validation |
| `OIDC_AUDIENCE` | Expected audience for forwarded ID tokens |
| `OIDC_REQUIRE_BOUND_OPAQUE` | Require `X-Alliance-ID-Token` binding (default `false`) |
| `OIDC_ALLOW_JWT_ACCESS_TOKENS` | Accept RS256 JWTs as access tokens (default `false`) |
| `TOKEN_HMAC_SECRET` | Shared HMAC secret for fmcpv1 tokens; enables API-token validation |
| `SERVICE_ID` | Service id this server answers for (default `ccdb`) |
| `TOKEN_REVOCATION_PATH` | Path to the token-issuer store, for revocation |
| `STAFF_GROUPS` | Comma-separated groups that grant cross-user access (default `cc-staff,scinet`) |
| `STAFF_LIST_PATH` | Optional JSON staff list, re-read on a short poll |
| `ALLOWED_HOSTS` | Host-header allow list for the DNS-rebinding guard |
| `ALLOWED_ORIGINS` | Parsed but currently unused; CORS is not implemented |
| `DNS_REBINDING_PROTECTION` | Enable the Host-header guard (default `true`) |
| `LOG_LEVEL` | `INFO` by default |
| `LOG_TIME_ZONE` | Zone for the `ts` field (default `America/Toronto`) |

The shipped defaults are SciNet's production configuration. `STAFF_GROUPS`
in particular contains a site group (`scinet`); other deployments should set
their own groups, or a group that does not exist to disable the group check.
An empty `STAFF_GROUPS` falls back to the default rather than clearing it.

**The DNS-rebinding guard is on by default** and only allows loopback hosts.
A real deployment must set `ALLOWED_HOSTS` to the public hostname it is
served under, or every request will be rejected with `403`.

## Staff (cross-user) access

A caller is staff when either:

- their group list intersects `STAFF_GROUPS`, or
- their username is in the file at `STAFF_LIST_PATH`.

The file is a JSON object with a `staffUsernames` list (`staff` and a bare
array are also accepted):

```json
{"staffUsernames": ["alice", "bob"]}
```

It is re-read on a 15-second timer when its mtime changes, so roster edits
take effect without a restart. The list is the override for sites whose IdP
does not release the expected group values. Protect the file: anyone who can
write it can grant cross-user access.

## Output schema and CCDB quirks

`src/ccdb_mcp/schemas.py` declares the output models. Several upstream quirks
are deliberate and pinned by `tests/test_schema_quirks.py` — do not "fix" them
silently:

- Some payload keys end in `?` (`primary_role_deactivated?`, `deactivated?`).
  They are not valid Python identifiers, so the models use aliases while the
  emitted schema keeps the real key.
- `start_date` and `expire_date` are empty strings on storage allocations,
  not `null`.
- The top-level person has no `role`; the nested `owner` and `members`
  persons do.
- `alloc_id` sequences are not contiguous; skipped ids are expired rows.
- A RAP roster can span several institutions, not just the owner's.
- Allocation keys depend on the resource family, so there is no fixed
  allocation schema. Unknown keys are preserved.
- The RAP tool returns the RAP unwrapped; the username tool nests RAPs under
  `raps`.
- The same person can appear on more than one of a person's RAPs.

## Development

```sh
uv sync --extra test
uv run --no-sync pytest -q          # 110 tests
uv run --no-sync pytest -q tests/test_schema_quirks.py
```

The tests do not need a directory, an IdP, or a live backend: the upstream API
is stubbed and the OIDC fixtures are local. `tests/fixtures/person_t10_scrubbed.json`
is synthetic and contains no real user data.

Formatting is not enforced by CI. Keep new code consistent with the
surrounding style.

## Deployment

This repository contains service code only. Deployment manifests, secrets,
and site-specific runbooks are maintained privately by SciNet.

The bundled `Dockerfile` is a two-stage build:

- dependencies are installed with `uv` from the committed lock file, then the
  build tooling is discarded;
- the runtime is a slim Python image with no pip and no package manager, and
  the process runs as an unprivileged user (`uid 10001`).

Both base images are pinned by digest; update them deliberately and rebuild.

A safe deployment:

- terminates TLS in front of the service;
- sets `ALLOWED_HOSTS` to the public hostname;
- supplies `ALLOCATIONS_API_KEY`, `TOKEN_HMAC_SECRET`, and the OIDC client
  values from a secret manager, never in the image;
- mounts the token-issuer store read-only at `TOKEN_REVOCATION_PATH`, so
  revocations propagate within the reload interval;
- exposes the MCP path (`/mcp` by default) and the health path for probes.

To accept the same tokens as the other MCP servers, every one of them must use
the same `TOKEN_HMAC_SECRET`; a token is still valid only for the server whose
`SERVICE_ID` matches its `svc` claim.

## Security

Please report vulnerabilities privately; see [SECURITY.md](SECURITY.md).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Issues are welcome. Pull requests are
reviewed by the maintainers, who decide whether and when to merge.

## Licence

MIT. See [LICENSE](LICENSE).
