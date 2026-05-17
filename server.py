#!/usr/bin/env python3
"""
Kali Security MCP Server
========================
Exposes a curated set of Kali Linux security tools as Model Context Protocol
(MCP) tools via FastMCP. Every tool validates and sanitises its inputs, runs
the underlying binary WITHOUT a shell (subprocess argument lists, never
``shell=True``), enforces a timeout, truncates large output, and returns a
formatted text report.

Tools: nmap, John the Ripper, OWASP ZAP, Nikto, sqlmap, WPScan, dirb,
searchsploit, plus a ``toolkit_info`` diagnostics tool.

AUTHORIZED USE ONLY
-------------------
Only scan or test systems that you own or are explicitly authorized in
writing to assess. Set ``MCP_ALLOWED_TARGETS`` to pin this server to an
approved CIDR scope; any target outside that scope is rejected before a
tool ever runs.
"""

import atexit
import functools
import ipaddress
import json
import logging
import os
import re
import secrets
import shlex
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import Literal, Optional
from urllib.parse import urlparse

from fastmcp import FastMCP

# ---------------------------------------------------------------------------
# Configuration -- everything tunable comes from environment variables.
# ---------------------------------------------------------------------------


def _env_int(name: str, default: int) -> int:
    try:
        return int((os.environ.get(name, "") or "").strip() or default)
    except ValueError:
        return default


OUTPUT_DIR = Path(os.environ.get("MCP_OUTPUT_DIR", "/data"))
WORDLIST_DIR = os.environ.get("MCP_WORDLIST_DIR", "/usr/share/wordlists")
DEFAULT_TIMEOUT = _env_int("MCP_DEFAULT_TIMEOUT", 300)
MAX_TIMEOUT = _env_int("MCP_MAX_TIMEOUT", 1800)
MAX_OUTPUT_BYTES = _env_int("MCP_MAX_OUTPUT_BYTES", 100_000)
TRANSPORT = (os.environ.get("MCP_TRANSPORT", "stdio") or "stdio").strip().lower()
HTTP_HOST = os.environ.get("MCP_HTTP_HOST", "0.0.0.0")
HTTP_PORT = _env_int("MCP_HTTP_PORT", 8000)
LOG_LEVEL = (os.environ.get("MCP_LOG_LEVEL", "INFO") or "INFO").upper()

ZAP_PATH = os.environ.get("ZAP_PATH", "/usr/share/zaproxy/zap.sh")
ZAP_HOST = os.environ.get("ZAP_HOST", "127.0.0.1")
ZAP_PORT = _env_int("ZAP_PORT", 8090)
# A blank key means "generate a fresh random key for this run". ZAP only
# listens on loopback inside the container, so the key never leaves the host.
ZAP_API_KEY = (os.environ.get("ZAP_API_KEY", "") or "").strip() or secrets.token_hex(16)

WPSCAN_API_TOKEN = (os.environ.get("WPSCAN_API_TOKEN", "") or "").strip()

# Wordlist files supplied to tools must live under one of these roots.
ALLOWED_WORDLIST_ROOTS = [Path("/usr/share"), Path(WORDLIST_DIR), OUTPUT_DIR]

# ---------------------------------------------------------------------------
# Logging -- MUST go to stderr. In stdio transport stdout is the MCP channel.
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL, logging.INFO),
    stream=sys.stderr,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
log = logging.getLogger("kali-mcp")


# ---------------------------------------------------------------------------
# Scope policy -- optional allow/deny CIDR lists enforced on every target.
# ---------------------------------------------------------------------------


def _parse_nets(value: str):
    nets = []
    for part in (value or "").split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            log.warning("Ignoring invalid network in scope config: %r", part)
    return nets


ALLOWED_NETS = _parse_nets(os.environ.get("MCP_ALLOWED_TARGETS", ""))
BLOCKED_NETS = _parse_nets(os.environ.get("MCP_BLOCKED_TARGETS", ""))


# ---------------------------------------------------------------------------
# Input validation helpers.
# ---------------------------------------------------------------------------

_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$"
)
_SAFE_TARGET_CHARS = re.compile(r"^[A-Za-z0-9.:/_-]+$")
_PORT_SPEC_RE = re.compile(r"^\d{1,5}(-\d{1,5})?(,\d{1,5}(-\d{1,5})?)*$")


def _check_scope_ips(ips, label: str) -> None:
    for ip in ips:
        for net in BLOCKED_NETS:
            if ip in net:
                raise ValueError(
                    f"Target {label} ({ip}) is in a blocked range ({net})."
                )
    if ALLOWED_NETS:
        for ip in ips:
            if not any(ip in net for net in ALLOWED_NETS):
                raise ValueError(
                    f"Target {label} ({ip}) is outside the authorized scope "
                    f"(MCP_ALLOWED_TARGETS). Refusing to proceed."
                )


def _check_scope_network(net) -> None:
    for blocked in BLOCKED_NETS:
        if net.overlaps(blocked):
            raise ValueError(f"Network {net} overlaps a blocked range ({blocked}).")
    if ALLOWED_NETS:
        same_ver = [a for a in ALLOWED_NETS if a.version == net.version]
        if not any(net.subnet_of(a) for a in same_ver):
            raise ValueError(
                f"Network {net} is not contained in the authorized scope "
                f"(MCP_ALLOWED_TARGETS). Refusing to proceed."
            )


def _check_scope_hostname(host: str) -> None:
    if not ALLOWED_NETS and not BLOCKED_NETS:
        return
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve hostname {host!r}: {exc}")
    ips = {ipaddress.ip_address(info[4][0]) for info in infos}
    _check_scope_ips(list(ips), host)


def validate_host(value: str, allow_cidr: bool = False) -> str:
    """Validate a hostname / IP / CIDR and enforce the scope policy."""
    value = (value or "").strip()
    if not value:
        raise ValueError("Target is empty.")
    if len(value) > 255 or not _SAFE_TARGET_CHARS.match(value):
        raise ValueError(f"Target contains illegal characters: {value!r}")

    if "/" in value:
        if not allow_cidr:
            raise ValueError("CIDR ranges are not allowed for this tool.")
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            raise ValueError(f"Invalid network: {value!r}")
        _check_scope_network(net)
        return str(net)

    try:
        ip = ipaddress.ip_address(value)
    except ValueError:
        ip = None
    if ip is not None:
        _check_scope_ips([ip], value)
        return str(ip)

    if not _HOSTNAME_RE.match(value):
        raise ValueError(f"Invalid hostname: {value!r}")
    _check_scope_hostname(value)
    return value


def validate_url(value: str) -> str:
    """Validate an http(s) URL and enforce the scope policy on its host."""
    value = (value or "").strip()
    if not value or len(value) > 2048:
        raise ValueError("URL is empty or too long.")
    if any(c.isspace() for c in value) or any(ord(c) < 32 for c in value):
        raise ValueError("URL contains whitespace or control characters.")
    parsed = urlparse(value)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("URL scheme must be http or https.")
    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host component.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        _check_scope_ips([ip], host)
    else:
        if not _HOSTNAME_RE.match(host):
            raise ValueError(f"Invalid host in URL: {host!r}")
        _check_scope_hostname(host)
    return value


def validate_token(value: str, pattern: str, label: str) -> str:
    """Ensure a free-form option matches a strict allowlist regex."""
    if not re.fullmatch(pattern, value or ""):
        raise ValueError(f"Invalid {label}: {value!r}")
    return value


def validate_port(port: int) -> int:
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise ValueError("port must be an integer between 1 and 65535.")
    return port


def validate_port_spec(ports: str) -> str:
    if not _PORT_SPEC_RE.match(ports or ""):
        raise ValueError(f"Invalid port specification: {ports!r}")
    if any(int(p) > 65535 for p in re.findall(r"\d+", ports)):
        raise ValueError(f"Port out of range in: {ports!r}")
    return ports


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False


def resolve_wordlist(path: str) -> str:
    """Resolve a wordlist path; it must exist and sit under an allowed root."""
    try:
        rp = Path(path).expanduser().resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError):
        raise ValueError(f"Wordlist not found: {path}")
    if not rp.is_file():
        raise ValueError(f"Wordlist is not a regular file: {path}")
    if not any(_is_within(rp, root) for root in ALLOWED_WORDLIST_ROOTS):
        roots = ", ".join(str(r) for r in ALLOWED_WORDLIST_ROOTS)
        raise ValueError(f"Wordlist must be located under one of: {roots}")
    return str(rp)


def resolve_input_file(path: str) -> str:
    """Resolve a user-supplied input file; it must sit under the output dir."""
    try:
        rp = Path(path).expanduser().resolve(strict=True)
    except (FileNotFoundError, RuntimeError, OSError):
        raise ValueError(f"File not found: {path}")
    if not rp.is_file():
        raise ValueError(f"Not a regular file: {path}")
    if not _is_within(rp, OUTPUT_DIR):
        raise ValueError(f"Input files must be located under {OUTPUT_DIR}.")
    return str(rp)


def new_output_path(prefix: str, suffix: str = "") -> Path:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    return OUTPUT_DIR / f"{prefix}_{secrets.token_hex(6)}{suffix}"


# ---------------------------------------------------------------------------
# Subprocess execution + output formatting.
# ---------------------------------------------------------------------------


def clamp_timeout(value) -> int:
    try:
        value = int(value)
    except (TypeError, ValueError):
        value = 0
    if value <= 0:
        return DEFAULT_TIMEOUT
    return min(value, MAX_TIMEOUT)


def run_command(cmd, timeout=None, cwd=None, input_text=None) -> dict:
    """Run a command as an argument list. shell=False ALWAYS (the default),
    which makes shell metacharacter injection structurally impossible."""
    timeout = clamp_timeout(timeout)
    start = time.monotonic()
    proc = subprocess.run(  # noqa: S603 - intentional, args are a validated list
        cmd,
        capture_output=True,
        text=True,
        timeout=timeout,
        cwd=cwd,
        input=input_text,
        env=os.environ.copy(),
        check=False,
    )
    return {
        "returncode": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
        "duration": time.monotonic() - start,
    }


def _truncate(text: str):
    data = text.encode("utf-8", "replace")
    if len(data) <= MAX_OUTPUT_BYTES:
        return text, False
    return data[:MAX_OUTPUT_BYTES].decode("utf-8", "ignore"), True


def _display_cmd(cmd) -> str:
    """Render a command for display, redacting secrets."""
    redacted, skip = [], False
    for tok in cmd:
        if skip:
            redacted.append("***")
            skip = False
            continue
        if tok in ("--api-token", "--password", "-pw"):
            redacted.append(tok)
            skip = True
        elif "api.key=" in tok:
            redacted.append(re.sub(r"api\.key=\S+", "api.key=***", tok))
        else:
            redacted.append(tok)
    return " ".join(shlex.quote(t) for t in redacted)


def format_report(title: str, cmd, result: dict, extra: str = "") -> str:
    out, truncated = _truncate(result.get("stdout", ""))
    err = (result.get("stderr", "") or "").strip()
    lines = [
        f"=== {title} ===",
        f"Command : {_display_cmd(cmd)}",
        f"Exit    : {result.get('returncode')}",
        f"Duration: {result.get('duration', 0):.1f}s",
        "",
    ]
    if extra:
        lines += [extra, ""]
    lines.append(out.strip() or "(no standard output)")
    if truncated:
        lines.append(f"\n[output truncated to {MAX_OUTPUT_BYTES} bytes]")
    if err:
        err_text, _ = _truncate(err)
        lines.append(f"\n--- stderr ---\n{err_text}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Error guard -- turns expected failures into clean text instead of raising.
# functools.wraps keeps the real signature so FastMCP builds correct schemas.
# ---------------------------------------------------------------------------


def guarded(fn):
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except ValueError as exc:
            return f"[input error] {exc}"
        except subprocess.TimeoutExpired as exc:
            return f"[timeout] {fn.__name__} exceeded its time limit ({exc.timeout}s)."
        except FileNotFoundError as exc:
            return f"[missing tool] Required binary not found: {exc.filename or exc}"
        except Exception as exc:  # noqa: BLE001 - last-resort guard for a tool call
            log.exception("Tool %s failed", fn.__name__)
            return f"[error] {fn.__name__} failed: {exc}"

    return wrapper


# ---------------------------------------------------------------------------
# OWASP ZAP daemon lifecycle.
# ---------------------------------------------------------------------------

_zap_proc = None
_zap_client = None


def _ensure_zap(startup_timeout: int = 180):
    """Lazily start the ZAP daemon and return a connected API client."""
    global _zap_proc, _zap_client
    try:
        from zapv2 import ZAPv2
    except ImportError:
        raise ValueError(
            "OWASP ZAP Python client is not installed. Rebuild the image "
            "with the INSTALL_ZAP build argument set to true."
        )

    proxy = f"http://{ZAP_HOST}:{ZAP_PORT}"
    if _zap_client is not None:
        try:
            _ = _zap_client.core.version
            return _zap_client
        except Exception:  # noqa: BLE001 - stale client, restart below
            _zap_client = None

    if not Path(ZAP_PATH).exists():
        raise ValueError(
            f"ZAP launcher not found at {ZAP_PATH}. Rebuild the image with "
            f"INSTALL_ZAP=true or set ZAP_PATH correctly."
        )

    zap_home = OUTPUT_DIR / "zap"
    zap_home.mkdir(parents=True, exist_ok=True)
    daemon_log = open(OUTPUT_DIR / "zap-daemon.log", "ab")  # noqa: SIM115
    cmd = [
        ZAP_PATH, "-daemon",
        "-host", ZAP_HOST,
        "-port", str(ZAP_PORT),
        "-dir", str(zap_home),
        "-config", f"api.key={ZAP_API_KEY}",
        "-config", f"api.addrs.addr.name={ZAP_HOST}",
        "-config", "api.addrs.addr.regex=false",
    ]
    log.info("Starting OWASP ZAP daemon on %s:%s ...", ZAP_HOST, ZAP_PORT)
    _zap_proc = subprocess.Popen(  # noqa: S603
        cmd, stdout=daemon_log, stderr=daemon_log, stdin=subprocess.DEVNULL
    )

    client = ZAPv2(apikey=ZAP_API_KEY, proxies={"http": proxy, "https": proxy})
    deadline = time.monotonic() + startup_timeout
    while time.monotonic() < deadline:
        if _zap_proc.poll() is not None:
            raise ValueError(
                "ZAP daemon exited during startup. See zap-daemon.log in the "
                "output directory."
            )
        try:
            version = client.core.version
            log.info("ZAP daemon ready (version %s).", version)
            _zap_client = client
            return client
        except Exception:  # noqa: BLE001 - daemon still warming up
            time.sleep(3)
    raise ValueError(f"ZAP daemon did not become ready within {startup_timeout}s.")


def _shutdown_zap() -> None:
    global _zap_proc
    if _zap_proc and _zap_proc.poll() is None:
        log.info("Stopping ZAP daemon.")
        try:
            _zap_proc.terminate()
            _zap_proc.wait(timeout=10)
        except Exception:  # noqa: BLE001
            try:
                _zap_proc.kill()
            except Exception:  # noqa: BLE001
                pass


atexit.register(_shutdown_zap)


# ---------------------------------------------------------------------------
# MCP server + tools.
# ---------------------------------------------------------------------------

mcp = FastMCP("kali-security-tools")


@mcp.tool()
@guarded
def nmap_scan(
    target: str,
    ports: Optional[str] = None,
    scan_type: Literal["tcp_syn", "tcp_connect", "udp", "ping"] = "tcp_syn",
    service_detection: bool = True,
    os_detection: bool = False,
    timing: int = 4,
    scripts: Literal[
        "none", "default", "safe", "vuln", "discovery", "auth", "banner"
    ] = "none",
    timeout: int = 0,
) -> str:
    """Run an nmap scan against a single host, IP, or CIDR network.

    target: hostname, IPv4/IPv6 address, or CIDR range (e.g. 192.168.1.0/24).
    ports: port spec such as '22,80,443' or '1-1024'. Default = nmap top ports.
    scan_type: tcp_syn (default, needs the NET_RAW capability), tcp_connect
        (works without extra capabilities), udp, or ping (host discovery only).
    service_detection: probe open ports for service/version banners (-sV).
    os_detection: attempt OS fingerprinting (-O, needs NET_RAW).
    timing: nmap timing template, 0 (slowest) to 5 (fastest). Default 4.
    scripts: run an NSE script category; 'none' disables scripts.
    timeout: max seconds for the scan (0 = server default).
    """
    tgt = validate_host(target, allow_cidr=True)
    if not 0 <= timing <= 5:
        raise ValueError("timing must be between 0 and 5.")

    flag = {"tcp_syn": "-sS", "tcp_connect": "-sT", "udp": "-sU", "ping": "-sn"}
    cmd = ["nmap", flag[scan_type], f"-T{timing}"]
    if scan_type != "ping":
        cmd.append("-Pn")
        if ports:
            cmd += ["-p", validate_port_spec(ports)]
        if service_detection:
            cmd.append("-sV")
        if os_detection:
            cmd.append("-O")
        if scripts != "none":
            cmd.append(f"--script={scripts}")
    cmd.append(tgt)

    result = run_command(cmd, timeout=timeout)
    return format_report(f"nmap {scan_type} scan: {tgt}", cmd, result)


@mcp.tool()
@guarded
def john_crack(
    hash_value: Optional[str] = None,
    hash_file: Optional[str] = None,
    hash_format: Optional[str] = None,
    wordlist: str = "/usr/share/wordlists/rockyou.txt",
    mode: Literal["wordlist", "single", "incremental"] = "wordlist",
    timeout: int = 0,
) -> str:
    """Crack password hashes with John the Ripper.

    Provide EITHER hash_value (one or more hashes, newline-separated) OR
    hash_file (a path to a hash file located under the output directory).
    hash_format: John format name, e.g. 'raw-md5', 'sha512crypt', 'nt'.
        Omit to let John auto-detect.
    wordlist: path to a wordlist (used in 'wordlist' mode only).
    mode: wordlist (default), single, or incremental.
    timeout: max seconds for the cracking run (0 = server default).
    """
    if hash_value and hash_file:
        raise ValueError("Provide either hash_value or hash_file, not both.")
    if not hash_value and not hash_file:
        raise ValueError("Provide a hash_value or a hash_file.")

    if hash_value:
        if len(hash_value) > 65536:
            raise ValueError("hash_value is too large.")
        target_file = new_output_path("john_hashes", ".txt")
        target_file.write_text(hash_value.strip() + "\n", encoding="utf-8")
        target_file = str(target_file)
    else:
        target_file = resolve_input_file(hash_file)

    fmt_args = []
    if hash_format:
        fmt = validate_token(hash_format, r"[A-Za-z0-9/+-]{1,40}", "hash format")
        fmt_args = [f"--format={fmt}"]

    pot = new_output_path("john", ".pot")
    session = new_output_path("johnsession", "")
    base = ["john", f"--pot={pot}", f"--session={session}", *fmt_args]

    if mode == "wordlist":
        crack_cmd = [*base, f"--wordlist={resolve_wordlist(wordlist)}", target_file]
    elif mode == "single":
        crack_cmd = [*base, "--single", target_file]
    else:
        crack_cmd = [*base, "--incremental", target_file]

    crack = run_command(crack_cmd, timeout=timeout)
    show = run_command(
        ["john", f"--pot={pot}", *fmt_args, "--show", target_file], timeout=60
    )
    cracked = (show.get("stdout") or "").strip() or "(no hashes cracked)"
    return format_report(
        f"John the Ripper ({mode} mode)",
        crack_cmd,
        crack,
        extra=f"--- cracked credentials ---\n{cracked}",
    )


@mcp.tool()
@guarded
def zap_scan(
    target_url: str,
    active_scan: bool = False,
    spider_minutes: int = 5,
    timeout: int = 0,
) -> str:
    """Scan a web application with OWASP ZAP.

    By default this performs a spider crawl plus passive analysis -- a
    non-intrusive baseline scan. Set active_scan=true to additionally run
    ZAP's active scanner, which sends real attack payloads; only do that
    against systems you are explicitly authorized to test.

    target_url: full http(s):// URL of the application to scan.
    active_scan: also run the intrusive active scanner.
    spider_minutes: maximum minutes to spend crawling (1-30).
    timeout: max seconds for the active scan phase (0 = server default).
    """
    url = validate_url(target_url)
    spider_minutes = max(1, min(int(spider_minutes), 30))
    zap = _ensure_zap()

    zap.urlopen(url)
    time.sleep(2)

    spider_id = zap.spider.scan(url)
    spider_deadline = time.monotonic() + spider_minutes * 60
    while int(zap.spider.status(spider_id)) < 100:
        if time.monotonic() > spider_deadline:
            zap.spider.stop(spider_id)
            break
        time.sleep(2)

    passive_deadline = time.monotonic() + 120
    while int(zap.pscan.records_to_scan) > 0:
        if time.monotonic() > passive_deadline:
            break
        time.sleep(2)

    active_summary = "active scan skipped (passive baseline only)"
    if active_scan:
        ascan_id = zap.ascan.scan(url)
        active_deadline = time.monotonic() + clamp_timeout(timeout)
        active_summary = "active scan completed"
        while int(zap.ascan.status(ascan_id)) < 100:
            if time.monotonic() > active_deadline:
                zap.ascan.stop(ascan_id)
                active_summary = "active scan stopped at the time limit"
                break
            time.sleep(5)

    alerts = zap.core.alerts(baseurl=url)
    buckets = {"High": [], "Medium": [], "Low": [], "Informational": []}
    for alert in alerts:
        buckets.setdefault(alert.get("risk", "Informational"), []).append(alert)

    lines = [
        f"=== OWASP ZAP scan: {url} ===",
        f"Spider + passive scan complete; {active_summary}.",
        f"Total alerts: {len(alerts)}",
        "",
    ]
    for risk in ("High", "Medium", "Low", "Informational"):
        items = buckets.get(risk, [])
        lines.append(f"[{risk}] {len(items)} alert(s)")
        grouped: dict = {}
        for alert in items:
            grouped.setdefault(alert.get("alert", "?"), set()).add(
                alert.get("url", "")
            )
        for name, urls in list(grouped.items())[:25]:
            lines.append(f"  - {name} ({len(urls)} location(s))")
        lines.append("")
    return "\n".join(lines).strip()


@mcp.tool()
@guarded
def nikto_scan(
    target: str,
    port: int = 80,
    ssl: bool = False,
    tuning: Optional[str] = None,
    timeout: int = 0,
) -> str:
    """Scan a web server for known vulnerabilities and misconfigurations
    with Nikto.

    target: hostname or IP address of the web server.
    port: TCP port of the web service (default 80).
    ssl: set true for HTTPS targets.
    tuning: optional Nikto -Tuning string selecting test categories, made of
        the characters 0-9 and a/b/c/d/e/x (e.g. '123bde').
    timeout: max seconds for the scan (0 = server default).
    """
    host = validate_host(target, allow_cidr=False)
    validate_port(port)

    cmd = ["nikto", "-h", host, "-p", str(port), "-nointeractive"]
    if ssl:
        cmd.append("-ssl")
    if tuning:
        cmd += ["-Tuning", validate_token(tuning, r"[0-9abcdex]{1,12}", "tuning string")]

    result = run_command(cmd, timeout=timeout)
    return format_report(f"Nikto scan: {host}:{port}", cmd, result)


@mcp.tool()
@guarded
def sqlmap_scan(
    url: str,
    data: Optional[str] = None,
    level: int = 1,
    risk: int = 1,
    technique: Optional[str] = None,
    dbms: Optional[str] = None,
    enumerate_dbs: bool = False,
    timeout: int = 0,
) -> str:
    """Test a URL for SQL injection vulnerabilities with sqlmap.

    Always runs in non-interactive --batch mode.

    url: target URL, typically including a parameter, e.g.
        http://host/page?id=1
    data: optional POST body string (switches the request to POST).
    level: test thoroughness, 1-5 (default 1).
    risk: payload risk level, 1-3 (default 1).
    technique: injection techniques, a subset of the letters B,E,U,S,T,Q.
    dbms: optional hint for the backend DBMS (e.g. 'mysql', 'postgresql').
    enumerate_dbs: also enumerate available databases (--dbs).
    timeout: max seconds for the run (0 = server default).
    """
    target = validate_url(url)
    if not 1 <= level <= 5:
        raise ValueError("level must be between 1 and 5.")
    if not 1 <= risk <= 3:
        raise ValueError("risk must be between 1 and 3.")

    out_dir = new_output_path("sqlmap", "")
    cmd = [
        "sqlmap", "-u", target, "--batch", "--disable-coloring",
        f"--level={level}", f"--risk={risk}", f"--output-dir={out_dir}",
    ]
    if data:
        if any(ord(c) < 32 and c != "\t" for c in data):
            raise ValueError("POST data contains control characters.")
        cmd += ["--data", data]
    if technique:
        cmd.append(
            f"--technique={validate_token(technique.upper(), r'[BEUSTQ]{1,6}', 'technique')}"
        )
    if dbms:
        cmd += ["--dbms", validate_token(dbms.lower(), r"[a-z0-9 _-]{1,30}", "dbms")]
    if enumerate_dbs:
        cmd.append("--dbs")

    result = run_command(cmd, timeout=timeout)
    return format_report(f"sqlmap: {target}", cmd, result)


@mcp.tool()
@guarded
def wpscan_scan(
    url: str,
    enumerate: Optional[str] = None,
    timeout: int = 0,
) -> str:
    """Scan a WordPress site with WPScan.

    url: the WordPress site URL.
    enumerate: optional WPScan --enumerate value, a comma-separated list of
        tokens such as 'vp' (vulnerable plugins), 'vt' (vulnerable themes),
        'u' (users), 'cb' (config backups). Example: 'vp,u'.
    timeout: max seconds for the scan (0 = server default).

    Set the WPSCAN_API_TOKEN environment variable to enrich results with the
    WPScan vulnerability database.
    """
    target = validate_url(url)
    cmd = [
        "wpscan", "--url", target, "--no-banner",
        "--format", "cli-no-color", "--random-user-agent",
    ]
    if enumerate:
        cmd += [
            "--enumerate",
            validate_token(
                enumerate, r"[A-Za-z]{1,3}(,[A-Za-z]{1,3})*", "enumerate option"
            ),
        ]
    if WPSCAN_API_TOKEN:
        cmd += ["--api-token", WPSCAN_API_TOKEN]

    result = run_command(cmd, timeout=timeout)
    return format_report(f"WPScan: {target}", cmd, result)


@mcp.tool()
@guarded
def dirb_scan(
    url: str,
    wordlist: str = "/usr/share/dirb/wordlists/common.txt",
    extensions: Optional[str] = None,
    timeout: int = 0,
) -> str:
    """Brute-force web content (directories and files) with dirb.

    url: base URL to scan, e.g. http://host/
    wordlist: path to a wordlist (default: the dirb 'common' list).
    extensions: optional comma-separated file extensions to append to each
        word, e.g. 'php,txt,bak'.
    timeout: max seconds for the scan (0 = server default).
    """
    target = validate_url(url)
    wl = resolve_wordlist(wordlist)

    cmd = ["dirb", target, wl, "-S", "-r"]
    if extensions:
        ext = validate_token(
            extensions, r"[A-Za-z0-9]{1,8}(,[A-Za-z0-9]{1,8})*", "extensions"
        )
        cmd += ["-X", "".join(f".{e}" for e in ext.split(","))]

    result = run_command(cmd, timeout=timeout)
    return format_report(f"dirb: {target}", cmd, result)


@mcp.tool()
@guarded
def searchsploit_search(
    query: str,
    exact: bool = False,
    max_results: int = 40,
) -> str:
    """Search the local Exploit-DB archive with searchsploit.

    This is a fully offline database lookup; it never contacts any target.

    query: search terms, e.g. 'apache 2.4 rce' or 'wordpress plugin xss'.
    exact: require exact word matches (-e).
    max_results: cap on the number of results shown (1-200).
    """
    query = (query or "").strip()
    if not query:
        raise ValueError("query is empty.")
    if len(query) > 200:
        raise ValueError("query is too long.")

    terms = []
    for term in re.split(r"\s+", query):
        if not term:
            continue
        if not re.fullmatch(r"[A-Za-z0-9._+/#-]{1,40}", term):
            raise ValueError(f"Invalid search term: {term!r}")
        terms.append(term)

    cmd = ["searchsploit", "--json", *(["-e"] if exact else []), *terms]
    result = run_command(cmd, timeout=60)

    try:
        data = json.loads(result.get("stdout") or "{}")
    except json.JSONDecodeError:
        return format_report(f"searchsploit: {query}", cmd, result)

    rows = data.get("RESULTS_EXPLOIT", []) + data.get("RESULTS_SHELLCODE", [])
    cap = max(1, min(int(max_results), 200))
    lines = [f"=== searchsploit: {query} ===", f"Matches: {len(rows)}", ""]
    for row in rows[:cap]:
        lines.append(f"  [{row.get('EDB-ID', '?')}] {row.get('Title', '?')}")
        if row.get("Path"):
            lines.append(f"        {row['Path']}")
    if len(rows) > cap:
        lines.append(f"\n... {len(rows) - cap} more results (raise max_results).")
    return "\n".join(lines)


@mcp.tool()
@guarded
def toolkit_info() -> str:
    """Report which security tools are installed and the active scan policy."""
    binaries = ["nmap", "john", "nikto", "sqlmap", "wpscan", "dirb", "searchsploit"]
    lines = ["=== Kali Security MCP toolkit ===", "", "Tools:"]
    for name in binaries:
        path = shutil.which(name)
        lines.append(f"  {'OK' if path else '--'}  {name:<14} {path or 'not installed'}")
    zap_ok = Path(ZAP_PATH).exists()
    lines.append(
        f"  {'OK' if zap_ok else '--'}  {'owasp-zap':<14} "
        f"{ZAP_PATH if zap_ok else 'not installed'}"
    )
    lines += [
        "",
        "Scan scope policy:",
        f"  allowed targets : {', '.join(str(n) for n in ALLOWED_NETS) or '(any -- no allowlist configured)'}",
        f"  blocked targets : {', '.join(str(n) for n in BLOCKED_NETS) or '(none)'}",
        "",
        "Limits:",
        f"  default timeout : {DEFAULT_TIMEOUT}s   max timeout: {MAX_TIMEOUT}s",
        f"  output directory: {OUTPUT_DIR}",
        f"  max output      : {MAX_OUTPUT_BYTES} bytes",
        f"  transport       : {TRANSPORT}",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point.
# ---------------------------------------------------------------------------


def main() -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    log.info("Kali Security MCP server starting (transport=%s).", TRANSPORT)
    if not ALLOWED_NETS:
        log.warning(
            "MCP_ALLOWED_TARGETS is not set: scans are NOT scope-restricted. "
            "Set it to an authorized CIDR range to enforce a target allowlist."
        )
    if TRANSPORT in ("http", "streamable-http", "sse"):
        mcp.run(transport="http", host=HTTP_HOST, port=HTTP_PORT)
    else:
        mcp.run()  # stdio transport (default)


if __name__ == "__main__":
    main()
