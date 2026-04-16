# Metatron

AI-powered penetration testing CLI. An LLM dispatches reconnaissance and exploitation tools, interprets the results, and stores findings in a MariaDB database with PDF/HTML report export.

**Stack:** Python 3.12 · MariaDB 11 · LM Studio (OpenAI-compatible API) · Docker

---

## Architecture

```
+---------------------+      +-----------------------------------+
|   Mac Host          |      |   Docker                          |
|                     |      |                                   |
|   LM Studio (MLX)  | <--- |   metatron (CLI)                  |
|   :1234             |      |   35+ pentest tools               |
|                     |      |                                   |
+---------------------+      |   mariadb :3306                   |
                             +-----------------------------------+
```

The LLM runs natively on the Mac with MLX GPU acceleration (recommended: any Qwen3.5 MoE model). Metatron and all tools run inside Docker. The container communicates with LM Studio via `host.docker.internal:1234`.

---

## Prerequisites

- Docker Desktop (Apple Silicon or x86_64)
- LM Studio with a loaded model and the local server running on port 1234
- ~2 GB free disk space for the image; ~1 GB additional for the SecLists wordlist volume

---

## First-time Setup

### 1. Provision the SecLists wordlist volume (one-time)

```bash
docker volume create seclists
docker run --rm -v seclists:/opt/seclists alpine/git \
    clone --depth=1 https://github.com/danielmiessler/SecLists.git /opt/seclists
```

### 2. Configure environment

Copy and edit the `.env` file:

```bash
cp .env.example .env   # if present, otherwise .env is already populated
```

Key variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `LLM_URL` | `http://host.docker.internal:1234/v1/chat/completions` | LM Studio API endpoint |
| `LLM_MODEL` | `qwen3.5-35b-a3b-heretic` | Model identifier shown in LM Studio server tab |
| `MYSQL_PASSWORD` | `metatron123` | MariaDB password |

### 3. Build the image

```bash
docker compose build metatron
```

Expected build time: 10–20 minutes on first run (downloads Go binaries, pip packages, exploitdb archive).

### 4. Start LM Studio

Open LM Studio, load your model, go to the **Local Server** tab, and click **Start Server**.

---

## Daily Use

```bash
# Start database
docker compose up -d mariadb

# Launch Metatron CLI
docker compose run --rm -it metatron
```

At the main menu, enter a target (IP, domain, or URL) and select the tools to run. The LLM analyses all tool output and stores findings in MariaDB.

---

## Tool Reference

Metatron currently ships 25 tools across two phases.

### Phase 1 — apt / git / pip

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

Additional Phase 1 tools available via LLM dispatch (not in numbered menu): hydra, john, ncrack, exiftool, dnsrecon, smbclient, onesixtyone, hping3, arp-scan, commix, netexec/nxc, ctfr, dirb

### Phase 2 — Go binaries / pip

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

Additional Phase 2 tools available via LLM dispatch: dnsx, feroxbuster, waybackurls, hakrawler

---

## LLM Tool Dispatch

The LLM can call any tool in `ALLOWED_TOOLS` (47 entries) by emitting `[TOOL: <command>]` tags. The container executes the command, captures stdout+stderr, and feeds the result back to the LLM for analysis.

To add a new tool to the allowed set, add it to `ALLOWED_TOOLS` in `src/tools.py` and rebuild the image.

---

## Docker Capabilities

The `metatron` container runs with two additional Linux capabilities:

| Capability | Required by |
|------------|-------------|
| `NET_RAW` | masscan, hping3, arp-scan, scapy |
| `NET_ADMIN` | masscan (rate-limited raw socket scanning) |

These are declared in `docker-compose.yml` and only apply to the Metatron container, not MariaDB.

---

## Database Schema

Five tables are auto-created on first MariaDB start (`docker/init.sql`):

| Table | Content |
|-------|---------|
| `history` | Every scan: target, timestamp, raw tool output |
| `vulnerabilities` | Parsed CVEs and findings per scan |
| `fixes` | Remediation recommendations |
| `exploits_attempted` | Tools run and outcomes |
| `summary` | AI-generated executive summary per scan |

### Inspect the database

```bash
docker compose exec mariadb mysql -umetatron -pmetatron123 metatron
```

---

## Reports

Metatron can export scan results as PDF or HTML. Reports are written inside the container to `/app/reports/` which maps to `./output/` on the host.

---

## Verification

After building, verify all tools are present:

```bash
# Phase 1 CLI tools
docker compose run --rm metatron bash -c "
  for t in sslscan testssl.sh sqlmap wafw00f enum4linux-ng snmpwalk onesixtyone \
            dnsrecon theHarvester searchsploit masscan exiftool hydra john nxc; do
    command -v \$t && echo 'OK' || echo \"MISSING: \$t\"
  done
"

# Phase 2 Go binaries
docker compose run --rm metatron bash -c "
  for t in nuclei httpx_pd subfinder dnsx katana ffuf feroxbuster gau waybackurls hakrawler dalfox; do
    command -v \$t && echo 'OK' || echo \"MISSING: \$t\"
  done
"

# SecLists wordlists
docker compose run --rm metatron bash -c "ls /opt/seclists/Discovery/Web-Content/ | head -5"
```

---

## Coverage

| Standard | Before | After Phase 1+2 |
|----------|--------|-----------------|
| NIST SP 800-115 Discovery | 70% | 92% |
| OWASP Testing Guide | 20% | 65% |
| MITRE ATT&CK TA0043 (Recon) | 80% | 95% |
| Nessus/Tenable parity | 20% | 72% |
| Burp Suite Pro parity | 12% | 68% |

**Commercial tools replaced:** Nessus Professional ($4,790/yr), Burp Suite Pro (~$475/yr), Qualys VMDR ($2,000–$20,000+/yr).

---

## Phase 3 Candidates

The following high-value tools are identified for a future Phase 3 expansion:

- **Secrets scanning:** gitleaks, TruffleHog
- **CMS scanning:** WPScan (WordPress), Droopescan (Drupal)
- **AD/Windows:** BloodHound.py, Kerbrute, evil-winrm, Responder
- **Cloud:** Pacu (AWS), ScoutSuite (multi-cloud), S3Scanner
- **Web:** smuggler (HTTP request smuggling), CORScanner (CORS), jwt_tool (JWT attacks)
- **Network pivot:** Chisel, Ligolo-ng

See `output/notes/factcheck_missed_tools.md` and `output/gap-close.md` Appendix C for full details.

---

## Project Layout

```
metatron-docker/
├── Dockerfile                  # Multi-stage build (go-builder + final)
├── docker-compose.yml          # Orchestrates mariadb + metatron
├── .env                        # DB creds and LLM URL (gitignored)
├── docker/
│   ├── init.sql                # MariaDB schema (auto-runs on first start)
│   └── entrypoint.sh           # Waits for MariaDB, then starts app
├── src/
│   ├── metatron.py             # Main CLI entry point
│   ├── db.py                   # MariaDB connection (env-var driven)
│   ├── llm.py                  # LM Studio OpenAI-compatible API client
│   ├── tools.py                # Tool runners + ALLOWED_TOOLS + TOOLS_MENU
│   ├── search.py               # DuckDuckGo search integration
│   ├── export.py               # PDF/HTML report export
│   └── requirements.txt        # Python dependencies
└── output/                     # Host-side report output (gitignored)
```

---

## Credits

Based on [METATRON](https://github.com/sooryathejas/METATRON) by sooryathejas. Ported to Docker, adapted for LM Studio (OpenAI-compatible API), and expanded with 35+ additional open-source pentesting tools.
