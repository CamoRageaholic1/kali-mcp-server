# Kali Security MCP Server

An [MCP](https://modelcontextprotocol.io) server that exposes a curated set of
Kali Linux penetration-testing tools as structured tools an MCP client (Claude
Desktop, etc.) can call. It runs inside a Kali Rolling container as a
**non-root user** with the **minimum Linux capabilities** each tool needs, and
validates every input before a subprocess is ever spawned.

> **Authorized use only.** These tools are for security testing of systems you
> own or have explicit written permission to assess. Scanning or attacking
> systems without authorization is illegal in most jurisdictions. Use the
> `MCP_ALLOWED_TARGETS` scope control to keep the server constrained to your
> approved engagement scope.

## Tools

| MCP tool | Underlying binary | Purpose |
|---|---|---|
| `nmap_scan` | nmap | Host discovery, port/service/OS detection, NSE scripts |
| `john_crack` | John the Ripper | Offline password-hash cracking (wordlist / incremental) |
| `zap_scan` | OWASP ZAP | Web app scan -- passive baseline, optional active scan |
| `nikto_scan` | nikto | Web server misconfiguration / known-issue scan |
| `sqlmap_scan` | sqlmap | SQL injection detection and DB enumeration (`--batch`) |
| `wpscan_scan` | wpscan | WordPress enumeration and vulnerability checks |
| `dirb_scan` | dirb | Web content / directory brute forcing |
| `searchsploit_search` | searchsploit | Offline Exploit-DB lookup |
| `toolkit_info` | -- | Diagnostics: tool versions, config, scope policy |

## Security model

- **Non-root.** The server process runs as the unprivileged `mcp` user
  (uid 1000). It never uses `sudo`.
- **Least capability.** The container drops `ALL` capabilities and adds back
  only `NET_RAW`, `NET_ADMIN`, and `NET_BIND_SERVICE` -- the set nmap needs for
  SYN/OS/UDP scans. File capabilities are set on `/usr/bin/nmap` so the
  unprivileged user can use them; every other tool runs with no elevated
  privileges at all.
- **No shell.** Every external command is executed from an argument list with
  `shell=False`. There is no shell to inject into -- metacharacters in input
  are inert.
- **Input validation.** Hostnames, IPs, CIDRs, URLs, ports, NSE script
  categories, and tokens are all checked against strict allowlists/regexes.
  Wordlist and input-file paths are resolved and confined to approved roots.
- **Scope enforcement.** When `MCP_ALLOWED_TARGETS` is set, every target
  (including resolved hostnames) is checked against the allowed CIDRs and
  refused if out of scope. `MCP_BLOCKED_TARGETS` is always denied and defaults
  to the cloud metadata IP (`169.254.169.254/32`) to blunt SSRF-style pivots.
- **Bounded execution.** Per-tool timeouts (capped by `MCP_MAX_TIMEOUT`) and
  output truncation (`MCP_MAX_OUTPUT_BYTES`) prevent runaway scans.

### Note on `no-new-privileges`

The Compose file deliberately does **not** set `no-new-privileges:true`. That
hardening flag causes the kernel to ignore file capabilities, which would break
nmap's privileged scan modes for the non-root user. The capabilities are
already minimized via `cap_drop: ALL` + a three-capability allowlist; that is
the intended trade-off. If you only need unprivileged nmap connect scans
(`-sT`), you may re-enable `no-new-privileges` and drop the `cap_add` block.

## Build

```bash
docker build -t kali-security-mcp:latest .
```

The full image is large (~2-3 GB) because it includes OWASP ZAP and its Java
runtime plus wordlists. For a much smaller image, skip those:

```bash
docker build --build-arg INSTALL_ZAP=false \
             --build-arg INSTALL_WORDLISTS=false \
             -t kali-security-mcp:slim .
```

(With ZAP omitted, `zap_scan` returns a clear "not installed" message and the
other tools are unaffected.)

## Configure

```bash
cp .env.example .env
```

Edit `.env`. At minimum, set `MCP_ALLOWED_TARGETS` to your engagement scope so
the server cannot be pointed at anything outside it.

## Run

### stdio transport (default -- for Claude Desktop and local clients)

```bash
docker compose run --rm mcp
```

or with plain Docker:

```bash
docker run -i --rm \
  --cap-drop ALL \
  --cap-add NET_RAW --cap-add NET_ADMIN --cap-add NET_BIND_SERVICE \
  --env-file .env \
  -v mcp-data:/data \
  kali-security-mcp:latest
```

### HTTP transport

Set `MCP_TRANSPORT=http` in `.env`, uncomment the `ports` block in
`docker-compose.yml`, then:

```bash
docker compose up
```

The server listens on `MCP_HTTP_HOST:MCP_HTTP_PORT` (default `8000`). Bind it
to `127.0.0.1` unless you have separately secured the endpoint.

## Claude Desktop configuration

Add to `claude_desktop_config.json` (stdio transport):

```json
{
  "mcpServers": {
    "kali-security": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "--cap-drop", "ALL",
        "--cap-add", "NET_RAW",
        "--cap-add", "NET_ADMIN",
        "--cap-add", "NET_BIND_SERVICE",
        "--env-file", "/absolute/path/to/.env",
        "-v", "mcp-data:/data",
        "kali-security-mcp:latest"
      ]
    }
  }
}
```

Use an absolute path for `--env-file`. Restart Claude Desktop after editing.

## Environment variables

| Variable | Default | Description |
|---|---|---|
| `MCP_OUTPUT_DIR` | `/data` | Where reports / crack results are written |
| `MCP_WORDLIST_DIR` | `/usr/share/wordlists` | Allowed root for wordlist paths |
| `MCP_DEFAULT_TIMEOUT` | `300` | Default per-tool timeout (seconds) |
| `MCP_MAX_TIMEOUT` | `1800` | Hard ceiling for any requested timeout |
| `MCP_MAX_OUTPUT_BYTES` | `100000` | Output truncation limit |
| `MCP_TRANSPORT` | `stdio` | `stdio` or `http` |
| `MCP_HTTP_HOST` | `0.0.0.0` | HTTP bind host (http transport only) |
| `MCP_HTTP_PORT` | `8000` | HTTP bind port (http transport only) |
| `MCP_LOG_LEVEL` | `INFO` | `DEBUG` / `INFO` / `WARNING` / `ERROR` |
| `MCP_ALLOWED_TARGETS` | _(empty)_ | Allowed target IPs/CIDRs; empty = unrestricted |
| `MCP_BLOCKED_TARGETS` | `169.254.169.254/32` | Always-denied IPs/CIDRs |
| `ZAP_PATH` | `/usr/share/zaproxy/zap.sh` | ZAP launcher path |
| `ZAP_HOST` | `127.0.0.1` | ZAP daemon bind host |
| `ZAP_PORT` | `8090` | ZAP daemon port |
| `ZAP_API_KEY` | _(auto)_ | ZAP API key; auto-generated per run if empty |
| `WPSCAN_API_TOKEN` | _(empty)_ | wpscan.com token for vuln-data enrichment |

## Files

| File | Purpose |
|---|---|
| `server.py` | FastMCP server: tool definitions, validation, execution |
| `Dockerfile` | Kali image with tools, non-root user, nmap capabilities |
| `docker-compose.yml` | Service definition with the capability policy |
| `entrypoint.sh` | Minimal launcher (stdout kept clean for stdio MCP) |
| `requirements.txt` | Python dependencies (`fastmcp`, `zaproxy`) |
| `.env.example` | Documented configuration template |

## Troubleshooting

- **nmap SYN scan reports permission errors** -- the container is missing
  `NET_RAW`, or `no-new-privileges` is set. Check the `cap_add` block; keep
  `no-new-privileges` disabled.
- **`zap_scan` says ZAP is unavailable** -- the image was built with
  `INSTALL_ZAP=false`, or `ZAP_PATH` is wrong. Rebuild with ZAP, or set
  `ZAP_PATH`.
- **"target out of scope"** -- the target is not inside `MCP_ALLOWED_TARGETS`
  (or matches `MCP_BLOCKED_TARGETS`). Adjust scope in `.env`.
- **Wordlist not found** -- the path must resolve under `MCP_WORDLIST_DIR`.
  Build with `INSTALL_WORDLISTS=true` or mount your own into that directory.
