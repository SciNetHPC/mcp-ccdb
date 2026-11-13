"""ASGI app for running the CCDB MCP server under uvicorn (production).

The middleware handles OIDC / API-token authentication and the
DNS-rebinding host guard; see ccdb_mcp.auth.
"""

from ccdb_mcp.config import Config
from ccdb_mcp.logging_setup import configure_logging
from ccdb_mcp.server import build_app

configure_logging()

config = Config.from_env()

_mcp, app = build_app(config)

__all__ = ["app", "config"]
