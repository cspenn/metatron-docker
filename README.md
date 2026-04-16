# Metatron

AI-powered penetration testing CLI. An LLM dispatches reconnaissance and exploitation tools, interprets results, performs live CVE research via web search, and generates a structured red team engagement brief — all stored in MariaDB with PDF/HTML export.

**Stack:** Python 3.12 · MariaDB 11 · LM Studio (OpenAI-compatible API + MCP) · Docker

---

## Architecture

```
+---------------------------+      +-----------------------------------+
|   Mac Host                |      |   Docker                          |
|                           |      |                                   |
|   LM Studio (MLX)        | <--- |   metatron (CLI)                  |
|   :1234                   |      |   35+ pentest tools               |
|   /v1/chat/completions    |      |                                   |
|   /api/v1/chat (MCP)      |      |   mariadb :3306                   |
|                           |      +-----------------------------------+
|   mcp/web-search          |
+---------------------------+
```

Two LM Studio endpoints are used:

| Endpoint | Purpose |
|----------|---------|
| `/v1/chat/completions` | Main tool-dispatch loop and scan analysis |
| `/api/v1/chat` | MCP-powered live CVE research and red team report generation |

The LLM runs natively on the Mac with MLX GPU acceleration. Metatron and all pentest tools run inside Docker. The container reaches LM Studio via `host.docker.internal:1234`.

---

## Scan Pipeline

Each scan runs six phases automatically:

```
Phase 1  Recon          Run selected pentest tools, collect raw output
Phase 2  LLM Analysis   Model identifies vulns, exploits, and risk level
Phase 3  Database        Save all findings to MariaDB
Phase 4  MCP Research    Live web searches for CVEs, PoCs, active exploitation
Phase 5  Red Team Brief  Synthesize into attack chains + operator directions
Phase 6  Export          Write PDF and HTML reports to ./output/
```

---

## Prerequisites

- Docker Desktop (Apple Silicon or x86_64)
- LM Studio 0.4.0 or newer, with a model loaded and the local server running on port 1234
- `mcp/web-search` configured in LM Studio (see setup below)
- ~2 GB free disk space for the image; ~1 GB additional for the SecLists wordlist volume

---

## First-time Setup

### 1. Provision the SecLists wordlist volume

Required for ffuf directory fuzzing. One-time operation.

```bash
docker volume create seclists
docker run --rm -v seclists:/opt/seclists alpine/git \
    clone --depth=1 https://github.com/danielmiessler/SecLists.git /opt/seclists
```

### 2. Configure LM Studio

**a. Load a model and start the server**

Open LM Studio, load your model (recommended: any Qwen 3 MoE or Gemma 4 model), go to the **Local Server** tab, and click **Start Server**.

**b. Enable MCP server access**

In LM Studio Server Settings, enable:
- **Allow calling servers from mcp.json**

**c. Add mcp/web-search to mcp.json**

In LM Studio, open the MCP editor (gear icon on the Local Server tab) and add:

```json
{
  "mcpServers": {
    "web-search": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-brave-search"],
      "env": {
        "BRAVE_API_KEY": "your-brave-api-key"
      }
    }
  }
}
```

The server ID in LM Studio must be `mcp/web-search` for Metatron to find it. If you use a different web search MCP server, update `_MCP_WEB_SEARCH` in `src/llm.py` accordingly.

**d. Copy the API key**

If LM Studio shows an API key on the Local Server tab, copy it — you will need it in step 3.

### 3. Configure the environment file

Edit `.env` in the project root:

```env
# MariaDB
MYSQL_ROOT_PASSWORD=metatron_root
MYSQL_DATABASE=metatron
MYSQL_USER=metatron
MYSQL_PASSWORD=metatron123

# LM Studio
LLM_URL=http://host.docker.internal:1234/v1/chat/completions
LLM_MODEL=your-model-name-as-shown-in-lmstudio
LLM_API_TOKEN=lm-studio-your-api-key-here

# MCP (set to false to skip live research and use training-data knowledge only)
LLM_MCP_ENABLED=true
```

**All environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_URL` | `http://host.docker.internal:1234/v1/chat/completions` | LM Studio OpenAI-compatible endpoint |
| `LLM_MODEL` | `qwen3.6-35b-a3b-heretic-mlx-mixed-4-8` | Model identifier shown in LM Studio server tab |
| `LLM_API_TOKEN` | _(empty)_ | Bearer token from LM Studio. Required if authentication is enabled |
| `LLM_MCP_ENABLED` | `true` | Set `false` to skip MCP research (uses training-data knowledge only) |
| `LLM_THINKING` | `false` | Set `true` only when running Gemma 4 to prepend `<\|think\|>` for explicit reasoning mode. Ignored by Qwen and other families. |
| `MYSQL_ROOT_PASSWORD` | `metatron_root` | MariaDB root password |
| `MYSQL_DATABASE` | `metatron` | Database name |
| `MYSQL_USER` | `metatron` | Application DB user |
| `MYSQL_PASSWORD` | `metatron123` | Application DB password |

### 4. Build the image

```bash
docker compose build metatron
```

Expected build time: 10–20 minutes on first run (downloads Go binaries, pip packages, exploitdb archive).

---

## Daily Use

```bash
# Start database
docker compose up -d mariadb

# Launch Metatron interactive CLI
docker compose run --rm -it metatron
```

At the main menu:

1. **New Scan** — enter a target, select tools, run analysis
2. **View History** — browse past sessions, export reports, generate red team briefs for existing sessions
3. **Exit**

### New Scan flow

```
[?] Enter target IP or domain: example.com

[ SELECT TOOLS TO RUN ]
  [1]  nmap              [14] theHarvester
  [2]  whois             [15] searchsploit
  [3]  whatweb           [16] masscan
  [4]  curl headers      [17] subfinder
  [5]  dig DNS           [18] nuclei
  [6]  nikto             [19] httpx_pd
  [7]  sslscan           [20] ffuf
  [8]  testssl           [21] katana
  [9]  sqlmap            [22] gau
  [10] wafw00f           [23] wapiti
  [11] enum4linux        [24] arjun
  [12] snmpwalk          [25] dalfox
  [13] dnsrecon
  [a]  Run all (except nikto)
  [n]  Run all + nikto (slow)

Choice(s) e.g. 1 2 4 or a: 1 2 4 5 14 17
```

After tools run, the LLM analyses all output, saves findings, then offers the MCP research and red team report phase.

---

## Tool Reference

### Phase 1 — System packages and pip

| Menu | Tool | Purpose |
|------|------|---------|
| 1 | nmap | Service/version fingerprinting |
| 2 | whois | Domain registration lookup |
| 3 | whatweb | Web technology fingerprinting |
| 4 | curl headers | HTTP/HTTPS header inspection |
| 5 | dig DNS | DNS record enumeration (A, MX, NS, TXT) |
| 6 | nikto | Web server misconfiguration scan |
| 7 | sslscan | SSL/TLS cipher and certificate scan |
| 8 | testssl.sh | 100+ TLS vulnerability checks |
| 9 | sqlmap | SQL injection (batch mode, level 3) |
| 10 | wafw00f | WAF fingerprinting |
| 11 | enum4linux | SMB/NetBIOS/Windows enumeration |
| 12 | snmpwalk | SNMP MIB tree enumeration |
| 13 | dnsrecon | DNS zone transfer and brute-force |
| 14 | theHarvester | Email, subdomain, and host OSINT |
| 15 | searchsploit | Offline CVE-to-exploit database search |
| 16 | masscan | High-speed full port scan (requires NET_RAW) |

Additional Phase 1 tools available via LLM dispatch (not in numbered menu):
`hydra`, `john`, `ncrack`, `hashid`, `exiftool`, `smbclient`, `onesixtyone`, `snmpbulkwalk`, `hping3`, `arp-scan`, `nc`, `netcat`, `commix`, `dirb`, `sslyze`

### Phase 2 — Go binaries and pip

| Menu | Tool | Purpose |
|------|------|---------|
| 17 | subfinder | Passive subdomain enumeration |
| 18 | nuclei | Template-based CVE/vulnerability scanner |
| 19 | httpx_pd | HTTP probing with tech detection |
| 20 | ffuf | Web content fuzzing (uses SecLists) |
| 21 | katana | JavaScript-aware web crawler |
| 22 | gau | Historical URL discovery (Wayback, AlienVault, etc.) |
| 23 | wapiti | Black-box OWASP web vulnerability scanner |
| 24 | arjun | HTTP parameter discovery |
| 25 | dalfox | XSS scanner |

Additional Phase 2 tools available via LLM dispatch:
`dnsx`, `feroxbuster`, `waybackurls`, `hakrawler`, `wapiti3`

---

## LLM Tool Dispatch

During analysis the LLM can call any tool in `ALLOWED_TOOLS` (48 entries) by emitting tags in its response:

```
[TOOL: nmap -sV 192.168.1.1]       runs any allowed CLI tool
[SEARCH: CVE-2021-44228 exploit]   DuckDuckGo web search
```

The container executes the command, captures stdout+stderr, compresses the output, and feeds it back to the LLM for the next analysis round. Up to 9 rounds per scan.

To add a new tool: add it to `ALLOWED_TOOLS` in `src/tools.py` and rebuild the image.

---

## MCP Research and Red Team Report

After the initial LLM analysis, Metatron offers a second AI pass using LM Studio's native MCP API.

### Phase 4 — Live vulnerability research

The model calls `mcp/web-search` autonomously for each significant finding:

```
[*] MCP research call via http://host.docker.internal:1234/api/v1/chat
[*] Research complete. 3 web search(es) performed.
  -> web_search: {'query': 'Subdomain Takeover Risk CVE CVSS exploit active exploitation'}
  -> web_search: {'query': 'CSP unsafe-eval wildcard XSS bypass 2025'}
```

Research covers: current CVE identifiers, CVSS scores, public proof-of-concept availability, active exploitation in the wild (ransomware groups, APTs), and typical patch deployment lag.

Only `web_search` is permitted — `image_search` and `news_search` are filtered out to keep the model focused on technical vulnerability intelligence.

### Phase 5 — Red team engagement brief

A second MCP call synthesizes scan data and research into a three-section report:

**Section 1: Vulnerability Assessment**
Per-finding assessment of real-world danger: actively exploited or theoretical, CVSS score, patch availability, confidence level (CONFIRMED / PROBABLE / THEORETICAL).

**Section 2: Attack Chains**
Numbered chains showing how vulnerabilities combine for maximum attacker impact:
```
CHAIN 1: Brand Impersonation via Subdomain Takeover
ENTRY: Identification of dangling CNAME record on a .dev subdomain
STEP: Claim defunct S3 bucket -> Host malicious content on cnn.com subdomain
STEP: Deploy phishing page -> Capture employee credentials
GOAL: Initial access to corporate internal networks
LIKELIHOOD: MEDIUM
DIFFICULTY: LOW
```

**Section 3: Red Team Directions**
Step-by-step operational guide with exact tool commands, expected output, documentation requirements, and MITRE ATT&CK IDs:
```
PHASE: Recon
ACTION: subfinder -d target.com -o subdomains.txt
EXPECTED_OUTPUT: List of discovered subdomains including staging environments
DOCUMENT: All identified subdomains for further takeover testing
MITRE: T1595
```

### Disabling MCP

Set `LLM_MCP_ENABLED=false` in `.env` to skip live research. The red team report will still be generated using the model's training-data knowledge only.

---

## Docker Capabilities

The `metatron` container runs with two additional Linux capabilities:

| Capability | Required by |
|------------|-------------|
| `NET_RAW` | masscan, hping3, arp-scan, scapy |
| `NET_ADMIN` | masscan (rate-limited raw socket scanning) |

These are declared in `docker-compose.yml` and apply only to the Metatron container, not MariaDB.

---

## Database Schema

Six tables are auto-created on first MariaDB start (`docker/init.sql`). Existing installations gain the `red_team_reports` table automatically on first use via `CREATE TABLE IF NOT EXISTS`.

| Table | Content |
|-------|---------|
| `history` | Every scan: target, timestamp, status |
| `vulnerabilities` | Parsed findings: name, severity, port, service, description |
| `fixes` | Remediation recommendations linked to vulnerabilities |
| `exploits_attempted` | Exploit attempts: tool, payload, result, notes |
| `summary` | Raw scan data, full AI analysis, risk level |
| `red_team_reports` | MCP research data, attack chains, red team directions |

### Inspect the database

```bash
docker compose exec mariadb mysql -umetatron -pmetatron123 metatron

-- Example queries
SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC;
SELECT vuln_name, severity, port, service FROM vulnerabilities WHERE sl_no = 1;
SELECT attack_chains FROM red_team_reports WHERE sl_no = 1\G
```

---

## Reports

All reports are written to `/app/reports/` inside the container, which maps to `./output/` on the host.

### Standard scan report (PDF or HTML)

Contains: target metadata, vulnerability table, fixes, exploit attempts, AI analysis summary.

Export from the CLI after any scan, or from View History for past sessions.

### Red team engagement brief (PDF or HTML)

Filename pattern: `redteam_report_<SL#>_<target>_<timestamp>.pdf`

Contains:
- **Section 1:** Vulnerability Assessment with live CVE research
- **Section 2:** Attack Chains with likelihood and difficulty ratings
- **Section 3:** Red Team Directions with MITRE ATT&CK mapping

The HTML version uses a dark-theme terminal aesthetic. The PDF version is suitable for client delivery.

---

## Verification

After building, verify all tools are present:

```bash
# Phase 1 CLI tools
docker compose run --rm metatron bash -c "
  for t in nmap whois whatweb curl dig nikto sslscan testssl.sh sqlmap wafw00f \
            enum4linux-ng snmpwalk dnsrecon theHarvester searchsploit masscan \
            hydra john ncrack exiftool; do
    command -v \$t && echo OK || echo \"MISSING: \$t\"
  done
"

# Phase 2 Go binaries
docker compose run --rm metatron bash -c "
  for t in nuclei httpx_pd subfinder dnsx katana ffuf feroxbuster gau waybackurls hakrawler dalfox; do
    command -v \$t && echo OK || echo \"MISSING: \$t\"
  done
"

# SecLists wordlists
docker compose run --rm metatron bash -c "ls /opt/seclists/Discovery/Web-Content/ | head -5"

# LM Studio connectivity (standard endpoint)
docker compose run --rm metatron curl -s \
  -H "Authorization: Bearer \$LLM_API_TOKEN" \
  http://host.docker.internal:1234/v1/models | python3 -m json.tool

# LM Studio native API (MCP endpoint)
docker compose run --rm metatron curl -s \
  -H "Authorization: Bearer \$LLM_API_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"model":"'"\$LLM_MODEL"'","input":"ping","context_length":64}' \
  http://host.docker.internal:1234/api/v1/chat
```

---

## Coverage

| Standard | Phase 1+2 | With MCP Research |
|----------|-----------|-------------------|
| NIST SP 800-115 Discovery | 92% | 92% |
| OWASP Testing Guide | 65% | 75% |
| MITRE ATT&CK TA0043 (Recon) | 95% | 95% |
| Nessus/Tenable parity | 72% | 80% |
| Burp Suite Pro parity | 68% | 74% |

MCP research closes the gap on post-discovery analysis: live CVE correlation, active exploitation context, and prioritised red team direction replace static training-data knowledge.

**Commercial tools replaced:** Nessus Professional ($4,790/yr), Burp Suite Pro (~$475/yr), Qualys VMDR ($2,000–$20,000+/yr).

---

## Troubleshooting

**401 Unauthorized on LLM calls**
LM Studio has authentication enabled. Copy the API key from the Local Server tab and set `LLM_API_TOKEN` in `.env`. Rebuild is not required — restart the container.

**403 Forbidden on `/api/v1/chat`**
The native MCP endpoint requires "Allow calling servers from mcp.json" to be enabled in LM Studio Server Settings.

**MCP research returns 0 searches**
Verify `mcp/web-search` appears in LM Studio's MCP server list and the server is running. The server ID must match exactly. Set `LLM_MCP_ENABLED=false` to bypass and continue without live research.

**masscan or hping3 permission errors**
These tools require `NET_RAW` capability. Confirm `cap_add: [NET_RAW, NET_ADMIN]` is present in `docker-compose.yml` and that Docker Desktop has not stripped capabilities (Linux hosts only: `--privileged` may be needed in some environments).

**exploitdb clone fails at build time**
The Dockerfile retries 3 times with a 5-second pause. On repeated failure, check network connectivity from the build host. The retry loop prevents a single transient failure from breaking the entire build.

**SecLists volume missing**
Run the one-time provisioning command from the setup section. The volume must exist before `docker compose run metatron` or ffuf will fail silently.

---

## Project Layout

```
metatron-docker/
├── Dockerfile                  # Multi-stage build (go-builder + final)
├── docker-compose.yml          # Orchestrates mariadb + metatron
├── .env                        # DB creds, LLM URL, API token (gitignored)
├── docker/
│   ├── init.sql                # MariaDB schema — 6 tables, auto-runs on first start
│   └── entrypoint.sh           # Waits for MariaDB readiness, then starts app
├── src/
│   ├── metatron.py             # Main CLI entry point and menu system
│   ├── db.py                   # MariaDB CRUD — all 6 tables
│   ├── llm.py                  # LM Studio client: analysis, MCP research, red team report
│   ├── tools.py                # Tool runners, ALLOWED_TOOLS (48 entries), TOOLS_MENU (25 entries)
│   ├── search.py               # DuckDuckGo search integration
│   ├── export.py               # PDF/HTML export for scan reports and red team briefs
│   └── requirements.txt        # Python dependencies
└── output/                     # Host-side report output (gitignored)
```

---

## Credits

Based on [METATRON](https://github.com/sooryathejas/METATRON) by sooryathejas. Ported to Docker, adapted for LM Studio (OpenAI-compatible API + MCP native API), and expanded with 35+ additional open-source pentesting tools and live vulnerability research.
