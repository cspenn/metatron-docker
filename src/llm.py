#!/usr/bin/env python3
"""
METATRON - llm.py
LM Studio interface (OpenAI-compatible API) for the Metatron model.
Builds prompts, handles AI responses, runs tool dispatch loop.
Model: configured via LLM_MODEL env var (default: Qwen 3.6 35B-A3B Heretic)
LM Studio must be running on the host at LLM_URL (default: http://localhost:1234)
"""

import os
import re
from urllib.parse import urlparse
import requests
from tools import run_tool_by_command
from search import handle_search_dispatch

LLM_URL        = os.environ.get("LLM_URL", "http://localhost:1234/v1/chat/completions")
MODEL_NAME     = os.environ.get("LLM_MODEL", "qwen3.6-35b-a3b-heretic-mlx-mixed-4-8")
MAX_TOKENS     = 8192
MAX_TOOL_LOOPS = 9
LLM_TIMEOUT    = 600

ENABLE_THINKING = os.environ.get("LLM_THINKING", "false").lower() == "true"

_parsed       = urlparse(LLM_URL)
LLM_BASE_URL  = f"{_parsed.scheme}://{_parsed.netloc}" if _parsed.netloc else LLM_URL.rstrip("/")
NATIVE_URL    = LLM_BASE_URL + "/api/v1/chat"
LLM_API_TOKEN = os.environ.get("LLM_API_TOKEN", "")
MCP_ENABLED   = os.environ.get("LLM_MCP_ENABLED", "true").lower() == "true"


def _build_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if LLM_API_TOKEN:
        headers["Authorization"] = f"Bearer {LLM_API_TOKEN}"
    return headers

_SYSTEM_PROMPT_BASE = """You are METATRON, an elite AI penetration testing assistant running on Parrot OS.
You are precise, technical, and direct. No fluff.

You have access to real tools. To use them, write tags in your response:

  [TOOL: nmap -sV 192.168.1.1]       -> runs nmap or any CLI tool
  [SEARCH: CVE-2021-44228 exploit]   -> searches the web via DuckDuckGo

Rules:
- Always analyze scan data thoroughly before suggesting exploits
- List vulnerabilities with: name, severity (critical/high/medium/low), port, service
- For each vulnerability, suggest a concrete fix
- If you need more information, use [SEARCH:] or [TOOL:]
- Format vulnerabilities clearly so they can be saved to a database
- Be specific about CVE IDs when you know them
- Always give a final risk rating: CRITICAL / HIGH / MEDIUM / LOW

Output format for vulnerabilities (use this exactly):
VULN: <name> | SEVERITY: <level> | PORT: <port> | SERVICE: <service>
DESC: <description>
FIX: <fix recommendation>

Output format for exploits:
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected result>
NOTES: <any notes>

End your analysis with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall summary>
IMPORTANT: Never use markdown bold (**text**) or headers (## text). Plain text only. No exceptions.
IMPORTANT RULES FOR ACCURACY:
- nmap filtered or no-response means INCONCLUSIVE not vulnerable
- Never assert a server version without seeing it in scan output
- Never infer CVEs from guessed versions
- curl timeouts and HTTP_CODE=000 mean the host is unreachable not exploitable
- ab and stress tools are not Slowloris unless confirmed
- Only assign CRITICAL if there is direct evidence of exploitability
- If evidence is weak mark severity as LOW with note: unconfirmed
- Never invent Metasploit module paths. Only cite a module path you have verified via web_search; otherwise write "no Metasploit module verified" and recommend a standalone PoC by GitHub repo path
- Never guess CVSS scores or vectors. If a CVSS value is not in your research output, write "CVSS: unknown -- requires NVD lookup"
- Never attribute exploitation to specific named ransomware groups (e.g. BlackCat, Clop, LockBit) without a citation in the research data. Default attribution is "opportunistic scanners and commodity malware operators" unless evidence supports otherwise
- Use the exact published vulnerability name from the original advisory (e.g. "regreSSHion" not "regresstty"). If unsure, write the CVE ID only"""

def _thinking_prefix() -> str:
    """Return the thinking-mode prefix appropriate for the loaded model family.

    Gemma 4 uses '<|think|>'. Qwen 3 handles thinking server-side via its
    native chat template, so no prefix is needed (injecting '<|think|>' would
    leak as literal text). Unknown families fall through to empty string.
    """
    if "gemma" in MODEL_NAME.lower():
        return "<|think|>\n"
    return ""


SYSTEM_PROMPT = (_thinking_prefix() + _SYSTEM_PROMPT_BASE) if ENABLE_THINKING else _SYSTEM_PROMPT_BASE


def strip_thinking(text: str) -> str:
    """Remove model reasoning blocks before parsing or display.

    Handles both known formats so the same code works regardless of which
    model is loaded in LM Studio:
      - Gemma 4:  <|channel>...<thought|>
      - Qwen3 / DeepSeek: <think>...</think>
    """
    # Gemma 4 reasoning channel — closing tag is thought|> or <thought|>
    text = re.sub(r'<\|channel>.*?thought\|>', '', text, flags=re.DOTALL)
    # Qwen3 / DeepSeek thinking blocks
    text = re.sub(r'<think>.*?</think>', '', text, flags=re.DOTALL)
    return text.strip()


def ask_llm(messages: list, temperature: float = 0.7) -> str:
    try:
        payload = {
            "model":       MODEL_NAME,
            "messages":    messages,
            "stream":      False,
            "max_tokens":  MAX_TOKENS,
            "temperature": temperature,
            "top_p":       0.9,
            "top_k":       10,
        }
        print(f"\n[*] Sending to {MODEL_NAME} via LM Studio...")
        resp = requests.post(LLM_URL, headers=_build_headers(), json=payload, timeout=LLM_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        response = strip_thinking(data["choices"][0]["message"]["content"])
        if not response:
            return "[!] Model returned empty response."
        return response
    except requests.exceptions.ConnectionError:
        return f"[!] Cannot connect to LM Studio at {LLM_URL}. Is LM Studio running with a model loaded?"
    except requests.exceptions.Timeout:
        return "[!] LM Studio timed out. Model may still be generating, try again."
    except requests.exceptions.HTTPError as e:
        return f"[!] LM Studio HTTP error: {e}"
    except (KeyError, IndexError):
        return "[!] Unexpected response format from LM Studio."
    except Exception as e:
        return f"[!] Unexpected error: {e}"


def extract_tool_calls(response: str) -> list:
    calls = []
    tool_matches   = re.findall(r'\[TOOL:\s*(.+?)\]',   response)
    search_matches = re.findall(r'\[SEARCH:\s*(.+?)\]', response)
    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))
    return calls


def summarize_tool_output(raw_output: str) -> str:
    if len(raw_output) < 500:
        return raw_output
    try:
        payload = {
            "model":       MODEL_NAME,
            "messages": [
                {"role": "system", "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown."},
                {"role": "user",   "content": f"Compress this tool output:\n{raw_output[:6000]}"}
            ],
            "stream":      False,
            "max_tokens":  512,
            "temperature": 0.2,
            "top_p":       0.9,
        }
        resp = requests.post(LLM_URL, headers=_build_headers(), json=payload, timeout=120)
        resp.raise_for_status()
        summary = resp.json()["choices"][0]["message"]["content"].strip()
        return summary if summary else raw_output
    except Exception:
        return raw_output


def ask_llm_native(prompt: str, integrations: list | None = None, temperature: float = 0.4) -> tuple:
    """
    Call the LM Studio native /api/v1/chat endpoint with optional MCP integrations.
    Returns (text_response: str, tool_calls: list).
    Each item in tool_calls is a dict with keys: tool, arguments, output.
    Falls back gracefully if the endpoint is unavailable.
    """
    if integrations is None:
        integrations = []
    payload = {
        "model":          MODEL_NAME,
        "input":          prompt,
        "stream":         False,
        "context_length": MAX_TOKENS,
        "temperature":    temperature,
        "top_p":          0.9,
    }
    if integrations:
        payload["integrations"] = integrations
    try:
        print(f"\n[*] MCP research call via {NATIVE_URL}")
        resp = requests.post(NATIVE_URL, headers=_build_headers(), json=payload, timeout=LLM_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        output_items = data.get("output", [])
        text_parts   = []
        tool_calls   = []
        for item in output_items:
            t = item.get("type", "")
            if t == "message":
                text_parts.append(item.get("content", ""))
            elif t == "tool_call":
                tool_calls.append({
                    "tool":      item.get("tool", ""),
                    "arguments": item.get("arguments", {}),
                    "output":    item.get("output", ""),
                })
        text = strip_thinking("\n".join(text_parts)).strip()
        if not text:
            text = "[!] MCP call returned no message content."
        return text, tool_calls
    except requests.exceptions.ConnectionError:
        return f"[!] Cannot connect to LM Studio native API at {NATIVE_URL}.", []
    except requests.exceptions.HTTPError as e:
        return f"[!] LM Studio native API error: {e}", []
    except Exception as e:
        return f"[!] Unexpected error from native API: {e}", []


_MCP_WEB_SEARCH = [{"type": "plugin", "id": "mcp/web-search", "allowed_tools": ["web_search"]}]


def _is_llm_error(text: str) -> bool:
    """Return True when text is a Metatron error sentinel rather than model output."""
    return not text or text.startswith("[!")


def research_vulnerabilities(vulns: list, target: str) -> dict:
    """
    Use mcp/web-search to look up CVEs, active PoCs, and patch status for the
    most significant vulnerabilities from a scan.

    vulns:  list of dicts from parse_vulnerabilities()
    target: the scan target string

    Returns {"research_text": str, "searches_performed": list}
    """
    critical_high = [v for v in vulns if v.get("severity", "").lower() in ("critical", "high")]
    if not critical_high:
        critical_high = vulns[:3]

    if not critical_high:
        return {"research_text": "No vulnerabilities found to research.",
                "searches_performed": []}

    vuln_summary = ""
    for v in critical_high:
        vuln_summary += (
            f"- {v['vuln_name']} | Severity: {v['severity']} | "
            f"Port: {v['port']} | Service: {v['service']}\n"
            f"  {v['description']}\n"
        )

    prompt = f"""You are researching vulnerabilities found during a penetration test.
Target: {target}

Vulnerabilities requiring research:
{vuln_summary}

For each vulnerability, use web_search to find the items below. If web_search returns no usable result for a field, write the literal string "not verified" for that field -- do not fill it from training-data memory.

1. Current CVE identifiers and CVSS 3.1 vector string (copy verbatim from NVD if found)
2. Whether public exploits or proof-of-concept code exist right now (cite GitHub repo paths or Exploit-DB IDs you actually saw in search results)
3. Whether actively exploited in the wild (cite the source advisory or threat-intel blog; do not name specific ransomware groups without a citation)
4. Current patch status, fixed-in version, and typical organizational deployment lag

After researching, summarize your findings using this format for each vulnerability:
RESEARCH: <vuln_name as published in original advisory>
CVE: <CVE IDs or "not verified">
CVSS: <full CVSS:3.1/... vector and base score, or "not verified">
EXPLOITS: <yes with cited repo/Exploit-DB ID, or "not verified", or "no public exploit found">
IN_THE_WILD: <yes with citation, or "not verified", or "no active exploitation reported">
PATCH_STATUS: <fixed-in version with date, or "not verified">
NOTES: <threat intelligence context, only facts you saw in search results>

Reminder: "not verified" is a valid and preferred answer when search did not surface evidence. An honest "not verified" is more useful than a confident guess.
"""

    if not MCP_ENABLED:
        text = ask_llm([{"role": "user", "content": prompt}], temperature=0.2)
        return {"research_text": text, "searches_performed": []}

    text, tool_calls = ask_llm_native(prompt, _MCP_WEB_SEARCH, temperature=0.2)
    if _is_llm_error(text):
        print(f"[!] MCP research failed ({text}). Falling back to training-data knowledge.")
        text = ask_llm([{"role": "user", "content": prompt}], temperature=0.2)
        tool_calls = []

    searches = [
        tc["tool"] + ": " + str(tc.get("arguments", {}))
        for tc in tool_calls
    ]
    print(f"[*] Research complete. {len(tool_calls)} web search(es) performed.")
    return {"research_text": text, "searches_performed": searches}


def _lint_report(chains: str, dirs: str) -> list:
    warnings = []
    phase_order = ["recon", "initial access", "execution", "persistence",
                   "discovery", "lateral movement", "collection", "exfiltration"]
    seen_indices = []
    for line in dirs.splitlines():
        m = re.match(r"\s*PHASE:\s*(.+?)\s*$", line, re.IGNORECASE)
        if m:
            name = m.group(1).strip().lower()
            if name in phase_order:
                seen_indices.append(phase_order.index(name))
    if seen_indices != sorted(seen_indices):
        warnings.append("phase order in RED_TEAM_DIRECTIONS is not monotonic")
    if re.search(r"<TARGET_IP>|<ATTACKER_PUBKEY>", dirs) and \
       "REPLACE BEFORE EXECUTION" not in dirs.upper():
        warnings.append("placeholders present without REPLACE BEFORE EXECUTION marker")
    if "authorized_keys" in dirs:
        if "mkdir -p" not in dirs or "chmod 600" not in dirs:
            warnings.append("authorized_keys persistence missing mkdir -p / chmod hardening")
    for chain_block in re.split(r"\n(?=CHAIN\s+\d+:)", chains):
        like = re.search(r"LIKELIHOOD:\s*(HIGH|MEDIUM|LOW)", chain_block, re.IGNORECASE)
        diff = re.search(r"DIFFICULTY:\s*(TRIVIAL|LOW|MEDIUM|HIGH)", chain_block, re.IGNORECASE)
        if like and diff:
            l, d = like.group(1).upper(), diff.group(1).upper()
            if l == "HIGH" and d == "HIGH":
                warnings.append("chain claims LIKELIHOOD:HIGH with DIFFICULTY:HIGH -- inconsistent")
            if l == "LOW" and d in ("TRIVIAL", "LOW"):
                warnings.append(f"chain claims LIKELIHOOD:LOW with DIFFICULTY:{d} -- inconsistent")
    return warnings


def generate_red_team_report(target: str, scan_result: dict, research: dict) -> dict:
    """
    Synthesize scan analysis + live research into a structured red team report.

    scan_result: dict returned by analyse_target()
    research:    dict returned by research_vulnerabilities()

    Returns {
        "research_data":       str,
        "attack_chains":       str,
        "red_team_directions": str,
    }
    """
    research_text = research.get("research_text", "No research data available.")

    vuln_list = ""
    for v in scan_result.get("vulnerabilities", []):
        vuln_list += (
            f"  - {v['vuln_name']} | {v['severity']} | "
            f"port {v['port']} | {v['service']}\n"
        )
    if not vuln_list:
        vuln_list = "  No structured vulnerabilities parsed.\n"

    exploit_list = ""
    for e in scan_result.get("exploits", []):
        exploit_list += f"  - {e['exploit_name']} via {e['tool_used']}: {e['payload']}\n"

    prompt = f"""You are a senior red team operator writing an engagement brief.
You have completed a scan and live vulnerability research on the target.

TARGET: {target}
RISK LEVEL: {scan_result.get("risk_level", "UNKNOWN")}
AI ANALYSIS SUMMARY: {scan_result.get("summary", "None")}

VULNERABILITIES FOUND:
{vuln_list}
EXPLOITS IDENTIFIED:
{exploit_list if exploit_list else "  None structured."}

LIVE VULNERABILITY RESEARCH:
{research_text}

Write a red team report with EXACTLY these three sections using these exact headers:

SECTION: VULNERABILITY_ASSESSMENT
For each vulnerability found, assess:
- Active exploitation in the wild (yes/no and by which threat actors)
- CVSS score if available from research
- Patch availability and typical organizational lag
- Confidence: CONFIRMED / PROBABLE / THEORETICAL

SECTION: ATTACK_CHAINS
Show how vulnerabilities combine for maximum attacker impact.
For each chain:
CHAIN <N>: <descriptive name>
ENTRY: <initial access vector>
STEP: <attacker action> -> <result>
STEP: <attacker action> -> <result>
GOAL: <final attacker objective>
LIKELIHOOD: HIGH|MEDIUM|LOW
DIFFICULTY: TRIVIAL|LOW|MEDIUM|HIGH

SECTION: RED_TEAM_DIRECTIONS
Step-by-step operational guide for the red team to implement and document the chains above.
For each step:
PHASE: <Recon|Initial Access|Execution|Persistence|Privilege Escalation|Lateral Movement|Collection|Exfiltration>
ACTION: <exact tool and command with flags>
EXPECTED_OUTPUT: <what successful execution looks like>
DOCUMENT: <what the operator must record in engagement notes>
MITRE: <ATT&CK technique ID>

Internal consistency rules -- the report must satisfy these or it is wrong:
- LIKELIHOOD and DIFFICULTY must be consistent with the exploitation cost described in research. A CVE requiring thousands of attempts over multiple hours cannot be LIKELIHOOD: HIGH or DIFFICULTY: LOW
- Every command in RED_TEAM_DIRECTIONS must be operationally complete. SSH key persistence requires mkdir -p, chmod 700 on .ssh, chmod 600 on authorized_keys, and an explicit absolute path -- never bare "~/.ssh"
- Phases in RED_TEAM_DIRECTIONS must appear in operational order: Recon -> Initial Access -> Execution -> Persistence -> Discovery -> Lateral Movement -> Collection -> Exfiltration. Skip phases that do not apply, but never reorder
- Every PHASE block must include all five fields (PHASE, ACTION, EXPECTED_OUTPUT, DOCUMENT, MITRE). Missing any field invalidates the block
- Tool names must be real and currently maintained. If you reference a Metasploit module, the path must come from the research data above. If no module was found in research, recommend the standalone PoC instead and say so explicitly
- Placeholders like <TARGET_IP> must be flagged as "REPLACE BEFORE EXECUTION" -- do not pretend the operator knows what to substitute
- If a chain depends on a configuration that scan data did not confirm (e.g. Nginx error_page reverse-proxy mode for CVE-2019-20372), state the precondition explicitly and mark the chain LIKELIHOOD: LOW until confirmed

Plain text only. No markdown. No bold. No ## headers. Use exact section headers shown.
Be operationally specific. Use real tool names and flags.
"""

    research_ok = not _is_llm_error(research_text)

    if not MCP_ENABLED or not research_ok:
        full_report = ask_llm([{"role": "user", "content": prompt}], temperature=0.2)
    else:
        full_report, extra_calls = ask_llm_native(prompt, _MCP_WEB_SEARCH, temperature=0.2)
        if _is_llm_error(full_report):
            print(f"[!] MCP report generation failed. Falling back to training-data knowledge.")
            full_report = ask_llm([{"role": "user", "content": prompt}], temperature=0.2)
        elif extra_calls:
            print(f"[*] Report generation used {len(extra_calls)} additional web search(es).")

    def _extract_section(text: str, name: str) -> str:
        m = re.search(
            rf"SECTION:\s*{re.escape(name)}\s*\n(.*?)(?=SECTION:|$)",
            text, re.DOTALL | re.IGNORECASE
        )
        return m.group(1).strip() if m else ""

    chains_text = _extract_section(full_report, "ATTACK_CHAINS")
    dirs_text   = _extract_section(full_report, "RED_TEAM_DIRECTIONS")
    for w in _lint_report(chains_text, dirs_text):
        print(f"[!] report-lint: {w}")
    return {
        "research_data":       research_text,
        "attack_chains":       chains_text,
        "red_team_directions": dirs_text,
    }


def run_tool_calls(calls: list) -> str:
    if not calls:
        return ""
    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")
        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"
        compressed = summarize_tool_output(output.strip())
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"
    return results


def _clean(line: str) -> str:
    return re.sub(r'\*+', '', line).strip()


def parse_vulnerabilities(response: str) -> list:
    vulns = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name": "", "severity": "medium",
                "port": "", "service": "",
                "description": "", "fix": ""
            }
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()
            j = i + 1
            while j < len(lines) and j <= i + 5:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1
            if vuln["vuln_name"]:
                vulns.append(vuln)
        i += 1
    return vulns


def parse_exploits(response: str) -> list:
    exploits = []
    lines = response.splitlines()
    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "", "tool_used": "",
                "payload": "", "result": "unknown", "notes": ""
            }
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()
            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1
            if exploit["exploit_name"]:
                exploits.append(exploit)
        i += 1
    return exploits


def parse_risk_level(response: str) -> str:
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


def analyse_target(target: str, raw_scan: str) -> dict:
    messages = [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": f"""TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable."""}
    ]

    final_response = ""

    for loop in range(MAX_TOOL_LOOPS):
        response = ask_llm(messages)
        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)
        final_response = response

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        tool_results = run_tool_calls(tool_calls)
        messages.append({"role": "assistant", "content": response})
        messages.append({"role": "user", "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
If analysis is complete, give the final RISK_LEVEL and SUMMARY."""})

    vulnerabilities = parse_vulnerabilities(final_response)
    exploits        = parse_exploits(final_response)
    risk_level      = parse_risk_level(final_response)
    summary         = parse_summary(final_response)

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(exploits)} exploits | Risk: {risk_level}")

    return {
        "full_response":   final_response,
        "vulnerabilities": vulnerabilities,
        "exploits":        exploits,
        "risk_level":      risk_level,
        "summary":         summary,
        "raw_scan":        raw_scan
    }


if __name__ == "__main__":
    print("[ llm.py test -- direct LM Studio connectivity check ]\n")
    try:
        r = requests.get(f"{LLM_BASE_URL}/v1/models", headers=_build_headers(), timeout=5)
        models = r.json()
        print(f"[+] LM Studio is running at {LLM_BASE_URL}")
        print(f"[+] Available models: {[m.get('id', '?') for m in models.get('data', [])]}")
    except Exception:
        print(f"[!] LM Studio not reachable at {LLM_BASE_URL}. Open LM Studio and start the Local Server.")
        exit(1)

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} -- nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
