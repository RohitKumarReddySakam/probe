<div align="center">

<img src="https://readme-typing-svg.demolab.com?font=Fira+Code&amp;weight=700&amp;size=28&amp;duration=3000&amp;pause=1000&amp;color=64FFDA&amp;center=true&amp;vCenter=true&amp;width=750&amp;lines=PROBE;Web+Vulnerability+Scanner;Headers+%7C+SSL+%7C+Ports+%7C+Forms+%7C+Crawler;CVSS+v3.1+Scoring+%7C+HTML%2FJSON+Reports" alt="Typing SVG" />

<br/>

[![Python](https://img.shields.io/badge/Python-3.11+-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![OWASP](https://img.shields.io/badge/OWASP-Top_10_2021-FF0000?style=for-the-badge)](https://owasp.org/Top10/)
[![CVSS](https://img.shields.io/badge/CVSS-v3.1-F97316?style=for-the-badge)](https://www.first.org/cvss/)
[![License](https://img.shields.io/badge/License-MIT-22C55E?style=for-the-badge)](LICENSE)

<br/>

> **Passive web vulnerability scanner: security headers, SSL/TLS, open ports, web crawling, form analysis, CVSS scoring, and downloadable reports.**

<br/>

[![Plugins](https://img.shields.io/badge/Plugins-5_Scan_Modules-64ffda?style=flat-square)](.)
[![Checks](https://img.shields.io/badge/Checks-50+-64ffda?style=flat-square)](.)
[![Reports](https://img.shields.io/badge/Reports-HTML_%2B_JSON-64ffda?style=flat-square)](.)
[![Passive](https://img.shields.io/badge/Mode-Passive_Only-22c55e?style=flat-square)](.)

</div>

> ⚠️ **AUTHORIZED USE ONLY** — Scan only websites you own or have explicit written permission to test.

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🎯 Purpose

Manual web security assessments involve checking dozens of headers, testing TLS, probing paths, and analyzing forms — all repetitive and error-prone. PROBE automates this:

| Plugin | Checks | Top Finding |
|--------|--------|------------|
| `web_headers` | 12 header checks | Missing HSTS, CSP, Wildcard CORS |
| `ssl_checker` | TLS version, cert, ciphers | TLS 1.0, expired cert |
| `open_ports` | 21 service profiles | Telnet 9.8, Redis 9.8 |
| `web_crawler` | URL discovery + 20 path probes | /.env, /.git/config accessible |
| `forms_checker` | CSRF, plaintext password, autocomplete | Missing CSRF token |

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🏗️ Architecture

```
Target URL
     │  POST /api/scan
     ▼
┌───────────────────────────────────────────────┐
│          Scan Runner (background thread)        │
│                                                 │
│  1. HTTP fetch      Headers + cookies + HTML    │
│  2. web_headers     12 security header checks   │
│  3. ssl_checker     TLS + certificate analysis  │
│  4. open_ports      21 service port profiles    │
│  5. web_crawler     URL + sensitive path probes │
│  6. forms_checker   CSRF + password field check │
└──────────────────────┬────────────────────────┘
                       │
       ┌───────────────▼──────────────┐
       │   CVSS Calculator            │
       │   Per-finding scores         │
       │   Composite 0–10             │
       │   Grade A+ to F              │
       └───────────────┬──────────────┘
                       │
       ┌───────────────▼──────────────┐
       │  HTML Report (standalone)    │
       │  JSON Report (structured)    │
       └──────────────────────────────┘
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔍 Scan Plugins

<details>
<summary><b>🔒 web_headers — 12 Security Header Checks</b></summary>

| Finding | Severity | CVSS |
|---------|----------|------|
| Missing Strict-Transport-Security | HIGH | 6.1 |
| Missing Content-Security-Policy | HIGH | 6.1 |
| Missing X-Content-Type-Options | MEDIUM | 4.3 |
| Missing X-Frame-Options | MEDIUM | 4.3 |
| Wildcard CORS (Access-Control: *) | MEDIUM | 5.4 |
| Exposed Server header | LOW | 2.6 |
| Exposed X-Powered-By header | LOW | 2.6 |

</details>

<details>
<summary><b>🔐 ssl_checker — TLS Configuration</b></summary>

| Finding | Severity | CVSS |
|---------|----------|------|
| TLS 1.0 supported (POODLE) | HIGH | 7.4 |
| TLS 1.1 supported | HIGH | 7.4 |
| Certificate expired | CRITICAL | 9.1 |
| Expiring in < 30 days | MEDIUM | 5.3 |
| Weak cipher (RC4/DES/EXPORT) | HIGH | 7.4 |

</details>

<details>
<summary><b>🔌 open_ports — 21 Service Profiles</b></summary>

| Service | Port | Severity | CVSS |
|---------|------|----------|------|
| Telnet | 23 | CRITICAL | 9.8 |
| Redis | 6379 | CRITICAL | 9.8 |
| MongoDB | 27017 | CRITICAL | 9.8 |
| SMB | 445 | HIGH | 8.1 |
| RDP | 3389 | HIGH | 8.1 |
| FTP | 21 | HIGH | 7.5 |

</details>

<details>
<summary><b>🕷️ web_crawler + forms_checker</b></summary>

- Crawls up to 20 pages (depth 2)
- Probes 20 sensitive paths: `/.env`, `/.git/config`, `/wp-config.php`, `/admin`…
- CSRF token detection in POST forms
- Password fields over HTTP detection
- Autocomplete attribute validation

</details>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## ⚡ Quick Start

```bash
# Clone the repository
git clone https://github.com/RohitKumarReddySakam/probe.git
cd probe

# Setup
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env

# Run
python app.py
# → http://localhost:5007
```

### 🐳 Docker

```bash
git clone https://github.com/RohitKumarReddySakam/probe.git
cd probe
docker build -t probe .
docker run -p 5007:5007 probe
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 🔌 API Reference

```bash
# Start scan
POST /api/scan
{
  "url": "https://example.com",
  "plugins": ["web_headers", "ssl_checker", "open_ports", "web_crawler", "forms_checker"]
}

# Get results
GET /api/scan/<scan_id>

# Download HTML report
GET /api/report/<scan_id>/html

# Download JSON report
GET /api/report/<scan_id>/json
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 📁 Project Structure

```
probe/
├── app.py                      # Flask application & REST API
├── wsgi.py                     # Gunicorn entry point
├── config.py
├── requirements.txt
├── Dockerfile
│
├── plugins/
│   ├── web_headers.py          # 12 security header checks
│   ├── ssl_checker.py          # TLS + certificate analysis
│   ├── open_ports.py           # 21 service port profiles
│   ├── web_crawler.py          # URL + path discovery
│   └── forms_checker.py        # CSRF + password analysis
│
├── core/
│   ├── cvss_calculator.py      # CVSS v3.1 + risk grades
│   └── report_generator.py     # HTML + JSON reports
│
├── templates/                  # Dashboard, Results, Reports
├── static/                     # CSS + JavaScript
└── tests/                      # 18 pytest tests
```

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

## 👨‍💻 Author

<div align="center">

**Rohit Kumar Reddy Sakam**

*DevSecOps Engineer & Security Researcher*

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Rohit_Kumar_Reddy_Sakam-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/rohitkumarreddysakam)
[![GitHub](https://img.shields.io/badge/GitHub-RohitKumarReddySakam-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/RohitKumarReddySakam)
[![Portfolio](https://img.shields.io/badge/Portfolio-srkrcyber.com-64FFDA?style=for-the-badge&logo=safari&logoColor=black)](https://srkrcyber.com)

> *"Passive observation is sufficient to find 80% of real-world vulnerabilities — no payload injection required."*

</div>

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif">

<div align="center">

**⭐ Star this repo if it helped you!**

[![Star](https://img.shields.io/github/stars/RohitKumarReddySakam/probe?style=social)](https://github.com/RohitKumarReddySakam/probe)

MIT License © 2025 Rohit Kumar Reddy Sakam

</div>
