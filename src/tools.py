#!/usr/bin/env python3
"""
METATRON - tools.py
Recon tool runners — all output returned as strings to feed into the LLM.
Tools used: nmap, whois, whatweb, curl, dig, nikto
"""

import subprocess


# ─────────────────────────────────────────────
# BASE RUNNER
# ─────────────────────────────────────────────

def run_tool(command: list, timeout: int = 120) -> str:
    """
    Execute a shell command, return combined stdout + stderr as string.
    Never crashes the program — always returns something.
    """
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        output = result.stdout.strip()
        errors = result.stderr.strip()

        if output and errors:
            return output + "\n[STDERR]\n" + errors
        elif output:
            return output
        elif errors:
            return errors
        else:
            return "[!] Tool returned no output."

    except subprocess.TimeoutExpired:
        return f"[!] Timed out after {timeout}s: {' '.join(command)}"
    except FileNotFoundError:
        return f"[!] Tool not found: {command[0]} — install it with: sudo apt install {command[0]}"
    except Exception as e:
        return f"[!] Unexpected error running {command[0]}: {e}"


# ─────────────────────────────────────────────
# INDIVIDUAL TOOLS
# ─────────────────────────────────────────────

def run_nmap(target: str) -> str:
    print(f"  [*] nmap -sV -sC -T4 --open {target}")
    return run_tool(["nmap", "-sV", "-sC", "-T4", "--open", target], timeout=180)


def run_whois(target: str) -> str:
    print(f"  [*] whois {target}")
    return run_tool(["whois", target], timeout=30)


def run_whatweb(target: str) -> str:
    print(f"  [*] whatweb -a 3 {target}")
    return run_tool(["whatweb", "-a", "3", target], timeout=60)


def run_curl_headers(target: str) -> str:
    print(f"  [*] curl -sI http://{target}")
    output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",
        f"http://{target}"
    ], timeout=20)

    https_output = run_tool([
        "curl", "-sI",
        "--max-time", "10",
        "--location",
        "-k",
        f"https://{target}"
    ], timeout=20)

    return f"[HTTP Headers]\n{output}\n\n[HTTPS Headers]\n{https_output}"


def run_dig(target: str) -> str:
    print(f"  [*] dig {target} ANY")
    a_record   = run_tool(["dig", "+short", "A",   target], timeout=15)
    mx_record  = run_tool(["dig", "+short", "MX",  target], timeout=15)
    ns_record  = run_tool(["dig", "+short", "NS",  target], timeout=15)
    txt_record = run_tool(["dig", "+short", "TXT", target], timeout=15)

    return (
        f"[A Records]\n{a_record}\n\n"
        f"[MX Records]\n{mx_record}\n\n"
        f"[NS Records]\n{ns_record}\n\n"
        f"[TXT Records]\n{txt_record}"
    )


def run_nikto(target: str) -> str:
    print(f"  [*] nikto -h {target}  (this may take a while...)")
    return run_tool(["nikto", "-h", target, "-nointeractive"], timeout=300)


# ── Phase 1: Network/Infrastructure ────────────────────────────────

def run_masscan(target: str) -> str:
    """High-speed port scan. Requires NET_RAW capability."""
    print(f"  [*] masscan -p1-65535 {target} --rate=5000")
    return run_tool(["masscan", f"{target}", "-p1-65535", "--rate=5000",
                     "--open-only", "-oG", "-"], timeout=300)


def run_sslscan(target: str) -> str:
    print(f"  [*] sslscan --no-colour {target}")
    return run_tool(["sslscan", "--no-colour", target], timeout=60)


def run_testssl(target: str) -> str:
    print(f"  [*] testssl.sh --severity HIGH {target}")
    return run_tool(["testssl.sh", "--severity", "HIGH", "--quiet",
                     "--color", "0", target], timeout=300)


def run_snmpwalk(target: str) -> str:
    print(f"  [*] snmpwalk -v2c -c public {target}")
    return run_tool(["snmpwalk", "-v2c", "-c", "public", target], timeout=60)


def run_onesixtyone(target: str) -> str:
    print(f"  [*] onesixtyone {target}")
    return run_tool(["onesixtyone", target, "public", "private",
                     "community", "manager"], timeout=30)


def run_enum4linux(target: str) -> str:
    print(f"  [*] enum4linux-ng -A {target}")
    return run_tool(["enum4linux-ng", "-A", target], timeout=120)


def run_dnsrecon(target: str) -> str:
    print(f"  [*] dnsrecon -d {target} -t std,axfr")
    return run_tool(["dnsrecon", "-d", target, "-t", "std,axfr"], timeout=120)


def run_searchsploit(query: str) -> str:
    print(f"  [*] searchsploit --json {query}")
    return run_tool(["searchsploit", "--json"] + query.split(), timeout=30)


def run_exiftool(target_path: str) -> str:
    print(f"  [*] exiftool {target_path}")
    return run_tool(["exiftool", "-json", target_path], timeout=30)


# ── Phase 1: Web ────────────────────────────────────────────────────

def run_sqlmap(target: str) -> str:
    """SQL injection scan. Uses --batch for non-interactive operation."""
    print(f"  [*] sqlmap -u {target} --batch --level 3 --risk 2")
    return run_tool(["sqlmap", "-u", target, "--batch", "--level", "3",
                     "--risk", "2", "--dbs", "--output-dir", "/tmp/sqlmap_out"],
                    timeout=600)


def run_wafw00f(target: str) -> str:
    print(f"  [*] wafw00f {target}")
    return run_tool(["wafw00f", target], timeout=30)


# ── Phase 1: OSINT ──────────────────────────────────────────────────

def run_theharvester(target: str) -> str:
    print(f"  [*] theHarvester -d {target} -b duckduckgo,bing,certspotter,crtsh,dnsdumpster")
    return run_tool(["theHarvester", "-d", target, "-b",
                     "duckduckgo,bing,certspotter,crtsh,dnsdumpster"],
                    timeout=120)


# ── Phase 2: Go Binaries ────────────────────────────────────────────

def run_subfinder(target: str) -> str:
    print(f"  [*] subfinder -d {target}")
    return run_tool(["subfinder", "-d", target, "-silent"], timeout=120)


def run_nuclei(target: str) -> str:
    print(f"  [*] nuclei -u {target} -severity critical,high,medium")
    return run_tool(["nuclei", "-u", target, "-j",
                     "-severity", "critical,high,medium",
                     "-disable-update-check", "-silent"], timeout=600)


def run_httpx_pd(target: str) -> str:
    print(f"  [*] httpx_pd -u {target}")
    return run_tool(["httpx_pd", "-u", target, "-json",
                     "-status-code", "-title", "-tech-detect",
                     "-follow-redirects", "-silent"], timeout=60)


def run_ffuf(target: str) -> str:
    wordlist = "/opt/seclists/Discovery/Web-Content/raft-large-files.txt"
    print(f"  [*] ffuf -u {target}/FUZZ -w {wordlist}")
    return run_tool(["ffuf", "-u", f"{target}/FUZZ", "-w", wordlist,
                     "-of", "json", "-o", "/tmp/ffuf_out.json",
                     "-mc", "200,301,302,403", "-t", "50", "-s"],
                    timeout=300)


def run_katana(target: str) -> str:
    print(f"  [*] katana -u {target} -d 3")
    return run_tool(["katana", "-u", target, "-json",
                     "-o", "/tmp/katana_out.jsonl", "-d", "3",
                     "-jc", "-silent"], timeout=180)


def run_gau(target: str) -> str:
    print(f"  [*] gau {target}")
    return run_tool(["gau", target, "--json",
                     "--o", "/tmp/gau_out.jsonl"], timeout=120)


def run_wapiti(target: str) -> str:
    print(f"  [*] wapiti -u {target} --level 2")
    return run_tool(["wapiti", "-u", target, "-f", "json",
                     "-o", "/tmp/wapiti_report.json",
                     "--level", "2", "--max-scan-time", "600"],
                    timeout=660)


def run_arjun(target: str) -> str:
    print(f"  [*] arjun -u {target}")
    return run_tool(["arjun", "-u", target, "-oJ",
                     "/tmp/arjun_params.json"], timeout=120)


def run_dalfox(target: str) -> str:
    print(f"  [*] dalfox url {target}")
    return run_tool(["dalfox", "url", target,
                     "--format", "json", "--no-spinner",
                     "-o", "/tmp/dalfox_results.json"], timeout=180)


# ─────────────────────────────────────────────
# MAIN RECON PIPELINE
# ─────────────────────────────────────────────

TOOLS_MENU = {
    # ── Existing ───────────────────────────────────────────────────
    "1":  ("nmap",           run_nmap),
    "2":  ("whois",          run_whois),
    "3":  ("whatweb",        run_whatweb),
    "4":  ("curl headers",   run_curl_headers),
    "5":  ("dig DNS",        run_dig),
    "6":  ("nikto",          run_nikto),
    # ── Phase 1 ────────────────────────────────────────────────────
    "7":  ("sslscan",        run_sslscan),
    "8":  ("testssl",        run_testssl),
    "9":  ("sqlmap",         run_sqlmap),
    "10": ("wafw00f",        run_wafw00f),
    "11": ("enum4linux",     run_enum4linux),
    "12": ("snmpwalk",       run_snmpwalk),
    "13": ("dnsrecon",       run_dnsrecon),
    "14": ("theHarvester",   run_theharvester),
    "15": ("searchsploit",   run_searchsploit),
    "16": ("masscan",        run_masscan),
    # ── Phase 2 ────────────────────────────────────────────────────
    "17": ("subfinder",      run_subfinder),
    "18": ("nuclei",         run_nuclei),
    "19": ("httpx_pd",       run_httpx_pd),
    "20": ("ffuf",           run_ffuf),
    "21": ("katana",         run_katana),
    "22": ("gau",            run_gau),
    "23": ("wapiti",         run_wapiti),
    "24": ("arjun",          run_arjun),
    "25": ("dalfox",         run_dalfox),
}


def run_default_recon(target: str) -> dict:
    print(f"\n[*] Starting recon on: {target}")
    print("─" * 50)

    results = {}
    results["nmap"]         = run_nmap(target)
    results["whois"]        = run_whois(target)
    results["whatweb"]      = run_whatweb(target)
    results["curl_headers"] = run_curl_headers(target)
    results["dig"]          = run_dig(target)

    print("─" * 50)
    print("[+] Recon complete.\n")
    return results


def run_single_tool(tool_key: str, target: str) -> str:
    if tool_key in TOOLS_MENU:
        _, func = TOOLS_MENU[tool_key]
        return func(target)
    return f"[!] Unknown tool key: {tool_key}"


def format_recon_for_llm(results: dict) -> str:
    output = ""
    for tool, data in results.items():
        output += f"\n{'='*50}\n"
        output += f"[ {tool.upper()} OUTPUT ]\n"
        output += f"{'='*50}\n"
        output += data.strip() + "\n"
    return output


ALLOWED_TOOLS = {
    # ── Existing ──────────────────────────────────────────────────
    "nmap", "whois", "whatweb", "curl", "dig", "nikto",

    # ── Phase 1: Network/Infrastructure ──────────────────────────
    "masscan",          # high-speed port scan (needs NET_RAW)
    "sslscan",          # SSL/TLS cipher scan
    "testssl.sh",       # 100+ TLS vulnerability checks
    "testssl",          # alias
    "snmpwalk",         # SNMP MIB tree enumeration
    "snmpbulkwalk",     # faster SNMP bulk retrieval
    "onesixtyone",      # SNMP community string scanner
    "smbclient",        # SMB share listing
    "enum4linux-ng",    # SMB/NetBIOS enumeration
    "enum4linux",       # legacy alias
    "nc",               # netcat banner grabbing
    "netcat",           # alias
    "hping3",           # TCP/IP packet crafter
    "arp-scan",         # ARP discovery (needs NET_RAW)
    "dnsrecon",         # DNS enumeration
    "exiftool",         # document metadata extraction
    "searchsploit",     # offline exploit database search
    "commix",           # command injection tester

    # ── Phase 1: Web ─────────────────────────────────────────────
    "sqlmap",           # SQL injection
    "wafw00f",          # WAF fingerprinting
    "dirb",             # directory brute-force
    "sslyze",           # TLS scanner (also Python lib)

    # ── Phase 1: Credential ───────────────────────────────────────
    "hydra",            # login brute-forcer
    "ncrack",           # Nmap-family auth cracker
    "john",             # password hash cracking
    "hashid",           # hash type identification

    # ── Phase 1: OSINT ────────────────────────────────────────────
    "theHarvester",     # email/subdomain/host harvesting
    "theharvester",     # lowercase alias

    # ── Phase 2: Go Binaries ──────────────────────────────────────
    "nuclei",           # template-based CVE/vuln scanner
    "httpx_pd",         # HTTP probing (ProjectDiscovery, renamed)
    "subfinder",        # passive subdomain enumeration
    "dnsx",             # fast DNS resolver/brute-forcer
    "katana",           # web crawler (JS-aware)
    "ffuf",             # web fuzzer (directory, parameter, vhost)
    "feroxbuster",      # recursive directory scanner
    "gau",              # historical URL discovery (multi-source)
    "waybackurls",      # Wayback Machine URL discovery
    "hakrawler",        # fast web crawler
    "dalfox",           # XSS scanner

    # ── Phase 2: Network ─────────────────────────────────────────
    "wapiti",           # black-box web vulnerability scanner
    "wapiti3",          # alias for wapiti
    "arjun",            # HTTP parameter discovery
}

def run_tool_by_command(command_str: str) -> str:
    parts = command_str.strip().split()
    if not parts:
        return "[!] Empty command."

    tool = parts[0].lower().split("/")[-1]
    if tool not in ALLOWED_TOOLS:
        return f"[!] Tool '{parts[0]}' is not permitted. Allowed: {ALLOWED_TOOLS}"

    return run_tool(parts)


def interactive_tool_run(target: str) -> str:
    print("\n[ SELECT TOOLS TO RUN ]")
    for key, (name, _) in TOOLS_MENU.items():
        print(f"  [{key}] {name}")
    print("  [a] Run all (except nikto)")
    print("  [n] Run all + nikto (slow)")

    choice = input("\nChoice(s) e.g. 1 2 4 or a: ").strip().lower()

    if choice == "a":
        results = run_default_recon(target)
        return format_recon_for_llm(results)

    if choice == "n":
        results = run_default_recon(target)
        results["nikto"] = run_nikto(target)
        return format_recon_for_llm(results)

    combined = {}
    for key in choice.split():
        if key in TOOLS_MENU:
            name, func = TOOLS_MENU[key]
            print(f"\n[*] Running {name}...")
            combined[name] = func(target)
        else:
            print(f"[!] Unknown option: {key}")

    return format_recon_for_llm(combined)


if __name__ == "__main__":
    target = input("Enter test target (IP or domain): ").strip()
    results = run_default_recon(target)
    print(format_recon_for_llm(results))
