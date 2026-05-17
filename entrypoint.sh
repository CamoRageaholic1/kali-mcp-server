#!/usr/bin/env bash
#
# Entrypoint for the Kali Security MCP server.
#
# Keep this minimal: under the default stdio transport, stdout is the MCP
# protocol channel and MUST NOT be polluted. All diagnostics go to stderr.
set -euo pipefail

OUTPUT_DIR="${MCP_OUTPUT_DIR:-/data}"
mkdir -p "${OUTPUT_DIR}" 2>/dev/null || true

echo "[entrypoint] starting kali-security-mcp (transport=${MCP_TRANSPORT:-stdio})" >&2

# exec so the Python process becomes PID 1's child directly and receives
# signals (SIGTERM on `docker stop`) without a shell in the way.
exec python3 /app/server.py "$@"
