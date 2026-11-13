#!/usr/bin/env bash
set -euo pipefail

CCDB_MCP_HOST="${CCDB_MCP_HOST:-0.0.0.0}"
CCDB_MCP_PORT="${CCDB_MCP_PORT:-8081}"

echo "[entrypoint] Starting CCDB MCP server on ${CCDB_MCP_HOST}:${CCDB_MCP_PORT}"
exec uvicorn app:app \
  --host "${CCDB_MCP_HOST}" \
  --port "${CCDB_MCP_PORT}" \
  --log-level info
