# 🔐 UBI-SEC Web Vulnerability Scanner

**UBI-SEC Web Vulnerability Scanner** is an educational Python-based web security scanner designed for **authorized penetration testing, cybersecurity labs, CTFs, and intentionally vulnerable applications**.

It combines basic web reconnaissance with automated vulnerability checks and generates terminal findings plus optional JSON reports.

> ⚠️ **Authorized Use Only:** Only scan systems you own or systems for which you have explicit permission to perform security testing.

---

## 🚀 Features

### 🔎 Reconnaissance

* Subdomain enumeration
* DNS-based common subdomain discovery
* Certificate Transparency lookup using `crt.sh`
* Basic web crawling
* Form discovery
* Same-domain link discovery

### 🛡️ Vulnerability Checks

| Vulnerability        | Detection                           |
| -------------------- | ----------------------------------- |
| SQL Injection        | Error-based indicators              |
| Reflected XSS        | Reflection / marker detection       |
| Form XSS             | Form input reflection               |
| CSRF                 | Missing token indicators            |
| SSTI                 | Template expression evaluation      |
| XXE                  | XML entity expansion indicators     |
| LFI / Path Traversal | File-content signatures             |
| Command Injection    | Time-based delay indicators         |
| Open Redirect        | Redirect parameter testing          |
| CORS                 | Wildcard / credential configuration |
| Security Headers     | Missing security headers            |
| Insecure Cookies     | Secure / HttpOnly flag checks       |
| Sensitive Files      | `.git`, `.env`, backups, configs    |
| IDOR                 | Numeric ID manual-review indicators |

---

## 📸 Scanner

```text
============================================================
              UBI-SEC WEB VULNERABILITY SCANNER
============================================================

[*] Target      : http://127.0.0.1:5000
[*] Deep crawl  : True
[*] Subdomains  : False

[HIGH]   SQL Injection
[HIGH]   Reflected XSS
[MEDIUM] CSRF
[LOW]    Security Headers
[INFO]   IDOR (manual review)

------------------------------------------------------------
Total findings: 5
------------------------------------------------------------

Scan completed by UBI-SEC Scanner — Author: ubi-sec
```

---

## ⚙️ Requirements

* Python **3.9+**
* `requests`
* `beautifulsoup4`
* `colorama`

---

## 📥 Installation

### Windows

```powershell
git clone https://github.com/ubi-sec/ubisec-scanner.git
cd ubisec-scanner

python -m venv venv
venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

If PowerShell blocks virtual-environment activation:

```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

Then activate again:

```powershell
venv\Scripts\Activate.ps1
```

---

### Linux / WSL / macOS

```bash
git clone https://github.com/ubi-sec/ubisec-scanner.git
cd ubisec-scanner

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
```

---

## ▶️ Usage

### Basic Scan

```bash
python ubisec_scanner.py -u http://127.0.0.1:5000
```

### Deep Crawl

The `--deep` option follows same-domain links and scans additional pages.

```bash
python ubisec_scanner.py -u http://127.0.0.1:5000 --deep
```

### Subdomain Enumeration

```bash
python ubisec_scanner.py -u https://example.com --subdomains
```

### Full Scan

```bash
python ubisec_scanner.py -u https://example.com --deep --subdomains
```

### Save JSON Report

```bash
python ubisec_scanner.py -u https://example.com --deep -o report.json
```

### Custom Request Delay

```bash
python ubisec_scanner.py -u https://example.com --delay 1
```

---

## 📄 JSON Report

Use:

```bash
python ubisec_scanner.py -u http://127.0.0.1:5000 -o report.json
```

The generated report contains:

```json
{
  "target": "http://127.0.0.1:5000",
  "author": "ubi-sec",
  "version": "2.0",
  "pages_scanned": 5,
  "findings": []
}
```

Each finding can contain:

* Vulnerability type
* Severity
* URL
* Description
* Evidence

---

## 🧪 Recommended Practice Targets

Do **not** use random websites for testing.

Use intentionally vulnerable environments such as:

* **OWASP Juice Shop**
* **DVWA**
* **bWAPP**
* Your own vulnerable Flask application
* Authorized CTF targets

These environments are designed for security testing and learning.

---

## ⚠️ Detection Limitations

This scanner is a **learning and triage tool**, not a replacement for professional penetration-testing tools or manual verification.

### SQL Injection

Primarily checks for recognizable database error messages.

It may miss:

* Blind SQLi
* Boolean-based SQLi
* Time-based SQLi
* WAF-filtered payloads
* Application-specific database behavior

### XSS

Reflection of a payload is treated as an indicator.

It does not guarantee that the payload is executable in the browser.

### CSRF

A missing visible CSRF token is only an indicator.

Applications may use other protections such as:

* SameSite cookies
* Origin validation
* Referer validation
* Custom request headers

### IDOR

IDOR detection is intentionally limited.

The scanner identifies numeric identifiers for **manual authorization testing**. It does not attempt to bypass authorization between different user accounts.

### Sensitive Files

A server returning HTTP `200` does not automatically mean the requested resource contains sensitive information.

Custom error pages can create false positives.

### Command Injection

Time-based detection can be affected by:

* Network latency
* Server load
* Rate limiting
* Proxies
* WAF behavior

Always manually verify results.

---

## 🏗️ Project Structure

```text
ubisec-scanner/
│
├── ubisec_scanner.py
├── requirements.txt
├── README.md
├── LICENSE
├── SECURITY.md
├── .gitignore
│
└── reports/
    └── .gitkeep
```

---

## 🗺️ Roadmap

Future improvements may include:

* [ ] Better crawler and URL normalization
* [ ] Improved false-positive filtering
* [ ] HTML report generation
* [ ] SARIF output
* [ ] Configurable payload files
* [ ] Authentication/session support
* [ ] Technology fingerprinting
* [ ] Rate limiting
* [ ] Better vulnerability evidence
* [ ] Improved severity classification
* [ ] Custom wordlists
* [ ] Plugin-based scanner architecture

---

## 🔐 Security & Responsible Use

UBI-SEC is intended for:

* Cybersecurity education
* Authorized penetration testing
* CTF competitions
* Local security labs
* Vulnerable web applications
* Security research on systems you are authorized to test

**Never scan a third-party system without authorization.**

See [`SECURITY.md`](SECURITY.md) for the project's security policy.

---

## 👨‍💻 Author

**ubi-sec**

Cybersecurity learning project focused on:

* Web Security
* Ethical Hacking
* Penetration Testing
* Vulnerability Assessment

* Red Teaming

---

## 📜 License

This project is licensed under the **MIT License**.

See [`LICENSE`](LICENSE) for details.

---

## ⭐ Disclaimer

This software is provided for educational and authorized security-testing purposes.

The author is not responsible for damage, disruption, data loss, or unauthorized activity resulting from misuse of this tool.
