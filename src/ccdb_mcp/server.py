"""FastMCP server for CCDB, shared and publicly reached.

Authentication model: a trusted front end can forward each user's OIDC
access token as ``Authorization: Bearer <token>``, and public MCP clients
present an fmcpv1 API token minted by a token-issuer.  Non-staff
callers are scoped to their own data: the username endpoint only returns
the caller's own CCDB record (the ``username`` argument must match the
authenticated subject), and the RAP endpoint only returns RAPs the caller
is a member of.  Staff (a ``STAFF_GROUPS`` match or staff-list membership)
may query other users' records and RAPs.  Non-staff cross-user requests
are refused before the upstream API is called.
"""

from __future__ import annotations

import logging
import time

import requests

from fastmcp import Context, FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.tools import ToolResult

from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse

from .auth import CCDBAuthMiddleware
from .config import Config
from .logging_setup import configure_logging
from .schemas import CcdbPersonWithRaps, CcdbRap

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 30  # seconds; without it a hung upstream is silent forever

def _rap_root(rap_id: str) -> str:
    """Canonicalise an identifier for comparison and lookup.

    RAP ids are lowercase by construction, but callers paste them from job
    scripts and papers, so matching is case-insensitive.  A sub-allocation
    id ``rrg-2030-00000-01`` addresses its parent RAP; other forms (a group
    name or an ``alloc_id``) are passed through and resolved upstream.
    """
    normalized = rap_id.strip().casefold()
    parts = normalized.split("-")
    if len(parts) == 4 and parts[-1].isdigit():
        return "-".join(parts[0:3])
    return normalized


def _rap_aliases(rap: dict) -> set[str]:
    """Every identifier a non-staff caller may use for one of their RAPs.

    CCDB accepts the RAP id, its group name and its allocation ids; the
    membership gate must accept the same aliases or a legitimate caller is
    denied for using a documented form.
    """
    aliases: set[str] = set()
    rapi = rap.get("rapi")
    if rapi:
        aliases.add(_rap_root(rapi))
    groupname = rap.get("groupname")
    if groupname:
        aliases.add(_rap_root(groupname))
    for allocation in rap.get("allocations") or []:
        alloc_id = allocation.get("alloc_id")
        if alloc_id:
            aliases.add(_rap_root(alloc_id))
    return aliases


class CcdbBackend:
    """Thin client for the Alliance Allocations API (server's own key)."""

    def __init__(self, config: Config) -> None:
        self._host = config.api_host
        self._headers: dict[str, str] | None = None
        if config.allocations_api_key:
            self._headers = {
                "Content-Type": "application/json",
                "Authorization": 'Token token="%s"' % (config.allocations_api_key),
                "include_research_areas": "true",
            }

    def get(self, path: str, tool: str, subject: str):
        """GET *path*, logging the outcome.  Returns the response, or None on
        failure.  *subject* is the authenticated caller, for the audit trail."""
        if self._host is None or self._headers is None:
            raise ToolError("CCDB backend is not configured on this server")
        started = time.monotonic()
        url = self._host + path
        try:
            response = requests.get(
                url, headers=self._headers, timeout=REQUEST_TIMEOUT
            )
        except requests.RequestException:
            logger.exception(
                "upstream request failed",
                extra={"tool": tool, "subject": subject, "url": url,
                       "ms": round((time.monotonic() - started) * 1000)},
            )
            return None

        ms = round((time.monotonic() - started) * 1000)
        if response.status_code != 200:
            # Status only: the body can carry another user's record.
            logger.warning(
                "upstream returned an error status",
                extra={"tool": tool, "subject": subject, "url": url,
                       "status": response.status_code, "ms": ms},
            )
            return None

        logger.info(
            "upstream request completed",
            extra={"tool": tool, "subject": subject, "url": url,
                   "status": response.status_code, "ms": ms},
        )
        return response


def _error_payload(code: str, message: str) -> dict:
    """CcdbRap/CcdbPersonWithRaps-shaped payload for a failed call.

    A tool that declares an output schema must return structured content
    even on failure: fastmcp turns a content-only ToolResult into an
    unstructured payload, and the MCP SDK then rejects it with
    "outputSchema defined but no structured output returned".

    ``ok``/``code`` are part of the declared output schema, so callers can
    branch on the failure class without parsing prose.  Codes are
    ``invalid_argument`` (bad input), ``not_found`` (no upstream record)
    and ``forbidden`` (cross-user access denied).
    """
    return {"ok": False, "code": code, "error": message}


def _not_found_error(message: str) -> dict:
    return _error_payload("not_found", message)


def _invalid_argument_error(message: str) -> dict:
    return _error_payload("invalid_argument", message)


def _normalize_text(value: str) -> str:
    """Trim user-supplied identifiers; both tools share this rule."""
    return value.strip()


def _blank_error(field: str) -> dict:
    return _invalid_argument_error(
        f"{field} must not be empty or whitespace")


def _ok_payload(user: dict) -> dict:
    """A successful person/RAP payload with an explicit success marker."""
    return {**user, "ok": True}


def _bearer(ctx: Context) -> str | None:
    """Extract the bearer token carried on the request, if any."""
    rctx = ctx.request_context
    if rctx is None:
        return None
    headers = rctx.request.headers
    raw = headers.get("authorization")
    if not raw:
        return None
    text = str(raw)
    if not text.startswith("Bearer "):
        return None
    return text[len("Bearer "):].strip() or None


def _bound_username(ctx: Context) -> str | None:
    """The username the auth middleware bound to this request's scope."""
    rctx = ctx.request_context
    if rctx is None:
        return None
    return rctx.request.scope.get("state", {}).get("user")


def _is_staff(ctx: Context) -> bool:
    """Whether the auth middleware deemed this caller staff (group match or
    staff-list membership)."""
    rctx = ctx.request_context
    if rctx is None:
        return False
    return bool(rctx.request.scope.get("state", {}).get("is_staff"))


def _not_member_error() -> dict:
    return _error_payload(
        "forbidden", "you may only access CCDB records for yourself"
    )


def build_server(config: Config, *, require_auth: bool = True) -> FastMCP:
    """Build a FastMCP server with the two CCDB tools.

    Non-staff callers are scoped to their own records; staff callers may
    query other users.  Identity comes from the auth middleware (see
    :mod:`.auth`); the tools re-read the bound subject so an identity can
    never be smuggled through tool arguments.  With ``require_auth=False``
    (tool listing only), no check is made that auth is configured.
    """
    if require_auth and not config.auth_enabled:
        raise SystemExit(
            "Neither OIDC_ISSUER_URL nor TOKEN_HMAC_SECRET is set; "
            "the CCDB endpoint would accept any caller."
        )

    mcp = FastMCP(
        "CCDB MCP Server",
        instructions=(
            "Tools operate only on the authenticated user's own CCDB "
            "records; staff may also query other users' records. "
            "Queries for other users by non-staff are always denied."
        ),
    )
    backend = CcdbBackend(config)

    @mcp.tool(output_schema=CcdbPersonWithRaps.model_json_schema())
    async def get_CCDB_allocations_from_username(
        username: str, ctx: Context
    ) -> ToolResult:
        """Get a user's CCDB allocation information, including Alliance
        resource allocation projects (RAPs) and their associated identifiers
        (rapi), plus other profile information (CCI, email address,
        institution, preferred language).

        Non-staff callers may only query their own record: *username* must
        match the authenticated username, and records for any other user are
        denied.  Staff callers (a ``STAFF_GROUPS`` match or staff-list
        membership) may query any username.  Matching is case-insensitive.
        Input is trimmed, and empty or whitespace-only input is rejected with
        an ``invalid_argument`` error.
        """
        subject = _bound_username(ctx)
        if not subject:
            raise ToolError("no authenticated user on this request")

        requested = _normalize_text(username)
        if not requested:
            payload = _blank_error("username")
            return ToolResult(
                content=payload["error"],
                structured_content=payload,
            )

        if requested.casefold() != subject.casefold() and not _is_staff(ctx):
            payload = _not_member_error()
            return ToolResult(
                content=payload["error"],
                structured_content=payload,
            )

        # Non-staff callers may only ever reach this line with their own
        # username; staff may query any user, so the lookup targets the
        # requested username either way.
        target = (
            requested if requested.casefold() != subject.casefold() else subject
        )
        response = backend.get(
            "/api/allocations/people/" + target,
            "get_CCDB_allocations_from_username",
            target,
        )

        if response is None:
            message = "No CCDB allocation record available for " + target
            return ToolResult(
                content=message,
                structured_content=_not_found_error(message))

        user = response.json()["person"]

        # content is left at None rather than repeating the username in a
        # label: the structured payload carries it, and the chatbot reads
        # structuredContent in preference to content anyway.
        return ToolResult(
            structured_content=_ok_payload(user),
            content=None)

    @mcp.tool(output_schema=CcdbRap.model_json_schema())
    async def get_CCDB_resource_allocation_project_details_from_RAP(
        rap_id: str, ctx: Context
    ) -> ToolResult:
        """Get the details of a CCDB resource allocation project (RAP) from
        the RAP ID, returned as a dictionary.

        Non-staff callers may only look up RAPs they are a member of.  Staff
        callers (a ``STAFF_GROUPS`` match or staff-list membership) may look
        up any RAP.  Matching is case-insensitive and input is trimmed;
        empty or whitespace-only input is rejected with an
        ``invalid_argument`` error.

        *rap_id* is normally the RAP id (``rrg-2030-00000``).  The upstream
        API also accepts the RAP's group name (``groupname``) and an
        ``alloc_id``; an allocation id resolves to its whole RAP.  For
        non-staff callers every such alias must belong to one of the
        caller's own RAPs.
        """
        subject = _bound_username(ctx)
        if not subject:
            raise ToolError("no authenticated user on this request")

        requested = _normalize_text(rap_id)
        if not requested:
            payload = _blank_error("rap_id")
            return ToolResult(
                content=payload["error"],
                structured_content=payload,
            )

        # Authorize by membership for non-staff: only RAPs present on the
        # caller's own CCDB record may be looked up (fail closed if the
        # record or the API is unavailable).  Staff need no self record, so
        # the lookup is skipped for them.
        rap = _rap_root(requested)
        if not _is_staff(ctx):
            person_response = backend.get(
                "/api/allocations/people/" + subject,
                "get_CCDB_resource_allocation_project_details_from_RAP",
                subject,
            )
            if person_response is None:
                message = "No CCDB allocation record available for " + subject
                return ToolResult(
                    content=message,
                    structured_content=_not_found_error(message))

            person = person_response.json().get("person") or {}
            raps = person.get("raps") or []
            allowed: set[str] = set()
            for own_rap in raps:
                allowed |= _rap_aliases(own_rap)
            if rap not in allowed:
                return ToolResult(
                    content=_not_member_error()["error"],
                    structured_content=_not_member_error())

        response = backend.get(
            "/api/allocations/raps/" + rap,
            "get_CCDB_resource_allocation_project_details_from_RAP",
            subject,
        )

        if response is None:
            message = "No CCDB record available for RAP " + rap_id
            return ToolResult(
                content=message,
                structured_content=_not_found_error(message))

        user = response.json()["rap"]

        # Same as the username tool: no label in content, the structured
        # payload is the data.
        return ToolResult(
            structured_content=_ok_payload(user),
            content=None)

    @mcp.custom_route(config.health_path, methods=["GET"])
    async def health_check(request: Request) -> PlainTextResponse:
        """Simple health endpoint for platform probes."""
        return PlainTextResponse("CCDB MCP server ok")

    @mcp.custom_route("/", methods=["GET"])
    async def root(request: Request) -> PlainTextResponse:
        """Return a basic status message for root requests."""
        return PlainTextResponse(
            "CCDB MCP server is running. Try /health for probe status.")

    return mcp


def _log_auth_config(config: Config) -> None:
    if not config.oidc_enabled:
        return
    logger.info(
        "OIDC validation configured",
        extra={
            "issuer": config.oidc_issuer_url,
            "audience": config.oidc_audience,
            "require_bound_opaque": config.oidc_require_bound_opaque,
            "allow_jwt_access_tokens": config.oidc_allow_jwt_access_tokens,
        },
    )
    if config.oidc_require_bound_opaque and not config.oidc_audience:
        logger.error(
            "OIDC_REQUIRE_BOUND_OPAQUE is set but OIDC_AUDIENCE is empty; "
            "every opaque access token will be rejected."
        )


def build_app(config: Config | None = None):
    """Build the (FastMCP server, Starlette app) pair, with auth middleware."""
    config = config or Config.from_env()
    _log_auth_config(config)
    server = build_server(config)
    app = server.http_app(
        path=config.path,
        middleware=[Middleware(CCDBAuthMiddleware, config=config)],
    )
    return server, app


# Module-level server for tool listing tooling
# (`fastmcp run server_entrypoint.py:mcp`); the serving path is build_app(),
# which wraps the freshly built server in the auth middleware.  require_auth
# is intentionally off here so `fastmcp run` can still list tools for local
# development tooling without auth configured; it is NOT a serving path.
mcp = build_server(Config.from_env(), require_auth=False)


def main():
    """Run the server with the authenticated HTTP app via uvicorn."""
    import uvicorn

    configure_logging()
    config = Config.from_env()
    logger.info("Starting CCDB MCP Server")

    _, app = build_app(config)
    uvicorn.run(app, host=config.host, port=config.port, log_level="info")


if __name__ == "__main__":
    main()
