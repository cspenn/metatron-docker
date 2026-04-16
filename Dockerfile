# =============================================================================
# Stage 1: Go builder
# Compiles Go-based tools that are not distributed as pre-built binaries
# =============================================================================
FROM python:3.12-slim AS go-builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN ARCH=${TARGETARCH:-amd64}; \
    curl -sSL "https://go.dev/dl/go1.26.2.linux-${ARCH}.tar.gz" | \
    tar -xz -C /usr/local

ENV PATH="/usr/local/go/bin:${PATH}"

RUN GOPATH=/usr/local GOBIN=/usr/local/bin \
    go install github.com/tomnomnom/waybackurls@latest

# =============================================================================
# Stage 2: Final image
# =============================================================================
FROM python:3.12-slim

# -----------------------------------------------------------------------------
# Apt packages: system tools, pentest suite, and nikto
# -----------------------------------------------------------------------------
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    whois \
    whatweb \
    curl \
    dnsutils \
    mariadb-client \
    git \
    perl \
    libnet-ssleay-perl \
    libjson-perl \
    libxml-writer-perl \
    openssl \
    sslscan \
    masscan \
    smbclient \
    ldap-utils \
    snmp \
    onesixtyone \
    netcat-openbsd \
    hping3 \
    arp-scan \
    dnsrecon \
    sqlmap \
    dirb \
    hydra \
    ncrack \
    john \
    libimage-exiftool-perl \
    unzip \
    wget \
    bsdmainutils \
    ca-certificates \
    && git clone --depth=1 https://github.com/sullo/nikto.git /opt/nikto \
    && chmod +x /opt/nikto/program/nikto.pl \
    && ln -sf /opt/nikto/program/nikto.pl /usr/local/bin/nikto \
    && rm -rf /var/lib/apt/lists/*

# -----------------------------------------------------------------------------
# SNMP MIBs: enable all MIBs
# -----------------------------------------------------------------------------
RUN sed -i 's/^mibs :$/mibs +ALL/' /etc/snmp/snmp.conf 2>/dev/null || \
    echo "mibs +ALL" >> /etc/snmp/snmp.conf

# -----------------------------------------------------------------------------
# testssl.sh
# -----------------------------------------------------------------------------
RUN git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/testssl.sh \
    && ln -s /opt/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# -----------------------------------------------------------------------------
# ExploitDB / searchsploit
# -----------------------------------------------------------------------------
RUN for i in 1 2 3; do \
        git clone --depth=1 https://gitlab.com/exploit-database/exploitdb.git /opt/exploitdb && break; \
        echo "exploitdb clone attempt $i failed, retrying..."; rm -rf /opt/exploitdb; sleep 5; \
    done \
    && ln -sf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit \
    && cp /opt/exploitdb/.searchsploit_rc /root/.searchsploit_rc 2>/dev/null || true

# -----------------------------------------------------------------------------
# commix
# -----------------------------------------------------------------------------
RUN git clone --depth=1 https://github.com/commixproject/commix.git /opt/commix \
    && ln -sf /opt/commix/commix.py /usr/local/bin/commix

# -----------------------------------------------------------------------------
# enum4linux-ng (not pip-installable; requires git clone)
# -----------------------------------------------------------------------------
RUN git clone --depth=1 https://github.com/cddmp/enum4linux-ng.git /opt/enum4linux-ng \
    && pip install --no-cache-dir -r /opt/enum4linux-ng/requirements.txt \
    && ln -sf /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng

# -----------------------------------------------------------------------------
# ctfr (not on PyPI; requires git clone)
# -----------------------------------------------------------------------------
RUN git clone --depth=1 https://github.com/UnaPibaGeek/ctfr.git /opt/ctfr \
    && pip install --no-cache-dir -r /opt/ctfr/requirements.txt \
    && ln -sf /opt/ctfr/ctfr.py /usr/local/bin/ctfr

# netexec: requires Rust + gcc compilers to build from source.
# Install separately on the host or use a Kali-based image layer.
# Excluded from this build to keep the image on python:3.12-slim.

# -----------------------------------------------------------------------------
# theHarvester (PyPI package is a stub 0.0.1; install from source)
# -----------------------------------------------------------------------------
RUN git clone --depth=1 https://github.com/laramies/theHarvester.git /opt/theHarvester \
    && pip install --no-cache-dir /opt/theHarvester

# -----------------------------------------------------------------------------
# Phase 2: ProjectDiscovery suite and other pre-built Go binaries
# -----------------------------------------------------------------------------
ARG TARGETARCH
ENV NUCLEI_VERSION=3.7.1
ENV HTTPX_PD_VERSION=1.9.0
ENV SUBFINDER_VERSION=2.13.0
ENV DNSX_VERSION=1.2.3
ENV KATANA_VERSION=1.5.0
ENV FFUF_VERSION=2.1.0
ENV GAU_VERSION=2.2.4

# ProjectDiscovery suite: nuclei, httpx, subfinder, dnsx, katana
RUN set -eux; ARCH=${TARGETARCH:-amd64}; \
    curl -sSLo /tmp/nuclei.zip \
      "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/nuclei.zip -d /usr/local/bin/ nuclei \
    && chmod +x /usr/local/bin/nuclei && rm /tmp/nuclei.zip; \
    \
    curl -sSLo /tmp/httpx.zip \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_PD_VERSION}/httpx_${HTTPX_PD_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/httpx.zip -d /usr/local/bin/ httpx \
    && mv /usr/local/bin/httpx /usr/local/bin/httpx_pd \
    && chmod +x /usr/local/bin/httpx_pd && rm /tmp/httpx.zip; \
    \
    curl -sSLo /tmp/subfinder.zip \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${SUBFINDER_VERSION}/subfinder_${SUBFINDER_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/subfinder.zip -d /usr/local/bin/ subfinder \
    && chmod +x /usr/local/bin/subfinder && rm /tmp/subfinder.zip; \
    \
    curl -sSLo /tmp/dnsx.zip \
      "https://github.com/projectdiscovery/dnsx/releases/download/v${DNSX_VERSION}/dnsx_${DNSX_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/dnsx.zip -d /usr/local/bin/ dnsx \
    && chmod +x /usr/local/bin/dnsx && rm /tmp/dnsx.zip; \
    \
    curl -sSLo /tmp/katana.zip \
      "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/katana.zip -d /usr/local/bin/ katana \
    && chmod +x /usr/local/bin/katana && rm /tmp/katana.zip

# ffuf (version-in-filename format: ffuf_VERSION_linux_ARCH.tar.gz)
RUN ARCH=${TARGETARCH:-amd64}; \
    curl -sSLo /tmp/ffuf.tar.gz \
      "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VERSION}/ffuf_${FFUF_VERSION}_linux_${ARCH}.tar.gz" \
    && tar xzf /tmp/ffuf.tar.gz -C /usr/local/bin/ ffuf \
    && chmod +x /usr/local/bin/ffuf && rm /tmp/ffuf.tar.gz

# feroxbuster (uses architecture-first naming: aarch64-linux-feroxbuster.zip)
RUN ARCH=${TARGETARCH:-amd64}; \
    FBARCH=$([ "$ARCH" = "arm64" ] && echo "aarch64-linux" || echo "x86_64-linux"); \
    curl -sSLo /tmp/feroxbuster.zip \
      "https://github.com/epi052/feroxbuster/releases/latest/download/${FBARCH}-feroxbuster.zip" \
    && unzip -q /tmp/feroxbuster.zip -d /usr/local/bin/ feroxbuster \
    && chmod +x /usr/local/bin/feroxbuster && rm /tmp/feroxbuster.zip

# gau (version-in-filename format: gau_VERSION_linux_ARCH.tar.gz)
RUN ARCH=${TARGETARCH:-amd64}; \
    curl -sSLo /tmp/gau.tar.gz \
      "https://github.com/lc/gau/releases/download/v${GAU_VERSION}/gau_${GAU_VERSION}_linux_${ARCH}.tar.gz" \
    && tar xzf /tmp/gau.tar.gz -C /usr/local/bin/ gau \
    && chmod +x /usr/local/bin/gau && rm /tmp/gau.tar.gz

# dalfox — non-fatal; pin ENV DALFOX_VERSION once correct version is confirmed
ENV DALFOX_VERSION=3.2.3
RUN ARCH=${TARGETARCH:-amd64}; \
    curl -sSLo /tmp/dalfox.tar.gz \
      "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox_${DALFOX_VERSION}_linux_${ARCH}.tar.gz" \
    && tar xzf /tmp/dalfox.tar.gz -C /usr/local/bin/ dalfox \
    && chmod +x /usr/local/bin/dalfox && rm /tmp/dalfox.tar.gz \
    || echo "WARNING: dalfox download failed — skipping"

# hakrawler — optional; non-fatal if release asset naming differs
RUN ARCH=${TARGETARCH:-amd64}; \
    curl -sSLo /tmp/hakrawler.zip \
      "https://github.com/hakluke/hakrawler/releases/latest/download/hakrawler_linux_${ARCH}.zip" \
    && unzip -q /tmp/hakrawler.zip -d /usr/local/bin/ hakrawler \
    && chmod +x /usr/local/bin/hakrawler && rm /tmp/hakrawler.zip \
    || echo "WARNING: hakrawler download failed — skipping"

# -----------------------------------------------------------------------------
# Copy Go-compiled binaries from builder stage
# -----------------------------------------------------------------------------
COPY --from=go-builder /usr/local/bin/waybackurls /usr/local/bin/

# -----------------------------------------------------------------------------
# Application setup
# -----------------------------------------------------------------------------
WORKDIR /app

COPY src/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# httpx_pd: pip installs the Python httpx CLI at /usr/local/bin/httpx which
# shadows the ProjectDiscovery httpx binary; re-download and place as httpx_pd.
ARG TARGETARCH
RUN ARCH=${TARGETARCH:-amd64}; \
    curl -sSLo /tmp/httpx2.zip \
      "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_PD_VERSION}/httpx_${HTTPX_PD_VERSION}_linux_${ARCH}.zip" \
    && unzip -q /tmp/httpx2.zip -d /tmp/httpx2/ httpx \
    && mv /tmp/httpx2/httpx /usr/local/bin/httpx_pd \
    && chmod +x /usr/local/bin/httpx_pd && rm -rf /tmp/httpx2.zip /tmp/httpx2

COPY src/*.py .

RUN mkdir -p /app/reports

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Update nuclei templates at build time
RUN nuclei -update-templates -disable-update-check 2>/dev/null || true

ENTRYPOINT ["/entrypoint.sh"]
CMD ["python", "metatron.py"]
