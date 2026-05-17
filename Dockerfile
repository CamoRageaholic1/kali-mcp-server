# syntax=docker/dockerfile:1
#
# Kali Security MCP Server
# ------------------------
# A Kali Rolling image that exposes a curated set of penetration-testing
# tools through a FastMCP server. Built to run as a non-root user with the
# minimum Linux capabilities each tool actually needs.
#
# Build:
#   docker build -t kali-security-mcp:latest .
#
# Slim build (skip ZAP + wordlists, much smaller / faster):
#   docker build --build-arg INSTALL_ZAP=false \
#                --build-arg INSTALL_WORDLISTS=false \
#                -t kali-security-mcp:slim .

FROM kalilinux/kali-rolling

# ---- Build-time options ----------------------------------------------------
ARG INSTALL_ZAP=true
ARG INSTALL_WORDLISTS=true
ARG MCP_UID=1000
ARG MCP_GID=1000
ARG DEBIAN_FRONTEND=noninteractive

# ---- Core tooling ----------------------------------------------------------
# nmap john nikto sqlmap wpscan dirb exploitdb cover the eight requested tools
# (searchsploit ships with exploitdb). libcap2-bin provides setcap.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        john \
        nikto \
        sqlmap \
        wpscan \
        dirb \
        exploitdb \
        python3 \
        python3-pip \
        python3-venv \
        libcap2-bin \
        procps \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# ---- OWASP ZAP (optional, large: pulls in a JRE) ---------------------------
RUN if [ "$INSTALL_ZAP" = "true" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends zaproxy && \
        rm -rf /var/lib/apt/lists/* ; \
    else \
        echo "Skipping ZAP install (INSTALL_ZAP=$INSTALL_ZAP)"; \
    fi

# ---- Wordlists (optional) --------------------------------------------------
# wordlists package + unpack rockyou.txt so John/dirb can use it directly.
RUN if [ "$INSTALL_WORDLISTS" = "true" ]; then \
        apt-get update && \
        apt-get install -y --no-install-recommends wordlists && \
        rm -rf /var/lib/apt/lists/* && \
        if [ -f /usr/share/wordlists/rockyou.txt.gz ]; then \
            gunzip -k /usr/share/wordlists/rockyou.txt.gz ; \
        fi ; \
    else \
        echo "Skipping wordlists install (INSTALL_WORDLISTS=$INSTALL_WORDLISTS)"; \
    fi

# ---- Python environment ----------------------------------------------------
# Isolated venv so we never fight Kali's externally-managed Python.
COPY requirements.txt /tmp/requirements.txt
RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir -r /tmp/requirements.txt \
    && rm /tmp/requirements.txt
ENV PATH="/opt/venv/bin:${PATH}"

# ---- Non-root user ---------------------------------------------------------
RUN groupadd -g "${MCP_GID}" mcp \
    && useradd -m -u "${MCP_UID}" -g "${MCP_GID}" -s /usr/sbin/nologin mcp

# ---- Capabilities ----------------------------------------------------------
# Only nmap needs elevated privileges (raw sockets for SYN/OS/UDP scans).
# File capabilities let the non-root user run it without sudo. The container
# must still be granted the matching caps at runtime (see docker-compose.yml).
RUN setcap cap_net_raw,cap_net_admin,cap_net_bind_service=eip /usr/bin/nmap

# ---- Application -----------------------------------------------------------
RUN mkdir -p /app /data \
    && chown -R mcp:mcp /app /data
COPY server.py /app/server.py
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh \
    && chown mcp:mcp /app/server.py

# ---- Runtime configuration defaults ----------------------------------------
ENV MCP_OUTPUT_DIR=/data \
    MCP_WORDLIST_DIR=/usr/share/wordlists \
    MCP_DEFAULT_TIMEOUT=300 \
    MCP_MAX_TIMEOUT=1800 \
    MCP_MAX_OUTPUT_BYTES=100000 \
    MCP_TRANSPORT=stdio \
    MCP_HTTP_HOST=0.0.0.0 \
    MCP_HTTP_PORT=8000 \
    MCP_LOG_LEVEL=INFO \
    ZAP_PATH=/usr/share/zaproxy/zap.sh \
    ZAP_HOST=127.0.0.1 \
    ZAP_PORT=8090

USER mcp
WORKDIR /data

# stdio is the default MCP transport; entrypoint execs server.py.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
