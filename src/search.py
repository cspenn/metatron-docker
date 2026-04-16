#!/usr/bin/env python3
"""
METATRON - search.py
Free web search via DuckDuckGo — no API key needed.
Also fetches and extracts plain text from URLs.
Used by LLM tool dispatch when AI writes [SEARCH: query]
"""

import re
import requests
from bs4 import BeautifulSoup
from ddgs import DDGS


def web_search(query: str, max_results: int = 5) -> str:
    print(f"  [*] Searching: {query}")
    try:
        with DDGS() as ddgs:
            results = list(ddgs.text(query, max_results=max_results))

        if not results:
            return "[!] No search results found."

        output = f"[WEB SEARCH RESULTS FOR: {query}]\n"
        output += "─" * 50 + "\n"
        for i, r in enumerate(results, 1):
            output += f"\n[{i}] {r['title']}\n"
            output += f"    URL     : {r['href']}\n"
            output += f"    Snippet : {r['body']}\n"

        return output

    except Exception as e:
        return f"[!] Search failed: {e}"


def search_cve(cve_id: str) -> str:
    print(f"  [*] Looking up {cve_id}...")
    ddg_results = web_search(f"{cve_id} vulnerability exploit details", max_results=3)
    mitre_url   = f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}"
    mitre_data  = fetch_page(mitre_url, max_chars=2000)
    return f"{ddg_results}\n\n[MITRE CVE LOOKUP: {cve_id}]\n{mitre_data}"


def search_exploit(service: str, version: str) -> str:
    query = f"{service} {version} exploit CVE vulnerability 2023 2024"
    return web_search(query, max_results=5)


def search_fix(vuln_name: str) -> str:
    query = f"how to fix {vuln_name} security mitigation patch"
    return web_search(query, max_results=3)


def fetch_page(url: str, max_chars: int = 3000) -> str:
    try:
        headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) Gecko/20100101 Firefox/120.0"}
        resp = requests.get(url, headers=headers, timeout=15)
        resp.raise_for_status()

        soup = BeautifulSoup(resp.text, "html.parser")

        for tag in soup(["script", "style", "nav", "footer", "header", "aside"]):
            tag.decompose()

        text  = soup.get_text(separator="\n", strip=True)
        lines = [l for l in text.splitlines() if l.strip()]
        clean = "\n".join(lines)

        if len(clean) > max_chars:
            clean = clean[:max_chars] + f"\n... [truncated at {max_chars} chars]"

        return clean

    except requests.exceptions.ConnectionError:
        return "[!] Could not connect to URL — check network."
    except requests.exceptions.Timeout:
        return "[!] Page fetch timed out."
    except requests.exceptions.HTTPError as e:
        return f"[!] HTTP error: {e}"
    except Exception as e:
        return f"[!] Fetch failed: {e}"


def handle_search_dispatch(query: str) -> str:
    query = query.strip()

    cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
    cve_match   = cve_pattern.search(query)
    if cve_match:
        return search_cve(cve_match.group())

    if any(word in query.lower() for word in ["exploit", "poc", "payload", "rce", "lfi", "sqli"]):
        return web_search(query + " exploit poc github", max_results=5)

    if any(word in query.lower() for word in ["fix", "patch", "mitigate", "harden", "secure"]):
        return search_fix(query)

    return web_search(query, max_results=5)


if __name__ == "__main__":
    print("[ search.py test ]\n")
    print("[1] General search")
    print("[2] CVE lookup")
    print("[3] Fetch a URL")
    choice = input("Choice: ").strip()

    if choice == "1":
        q = input("Query: ").strip()
        print(web_search(q))
    elif choice == "2":
        cve = input("CVE ID (e.g. CVE-2021-44228): ").strip()
        print(search_cve(cve))
    elif choice == "3":
        url = input("URL: ").strip()
        print(fetch_page(url))
