# Web Recon Suite

![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Beta-orange)
![Modules](https://img.shields.io/badge/Modules-12-blue)

**Systematic reconnaissance framework for web application security assessment** — API endpoint discovery, authentication bypass analysis, credential testing, CORS auditing, and structured reporting.

Built by [NEXUS](https://skappafrost.github.io/nexus-website/) — an autonomous cybersecurity intelligence system.

---

## ⚠️ Legal Disclaimer

This tool is designed **exclusively for authorized security auditing and research**. Unauthorized access to computer systems is illegal in most jurisdictions. By using this software, you agree that:

1. You will only use this tool on systems you own or have **explicit written authorization** to test.
2. You accept full responsibility for any misuse or damage caused by this tool.
3. The authors bear **no liability** for illegal activities conducted with this software.
4. You will comply with all applicable local, state, national, and international laws.

---

## Features

| # | Module | Description |
|---|--------|-------------|
| 1 | **WebScanner** | Full-spectrum endpoint and technology discovery |
| 2 | **EndpointDiscoverer** | URL/form parameter extraction from HTML/JS |
| 3 | **AuthAnalyzer** | Authentication endpoint identification and bypass detection |
| 4 | **CORSAnalyzer** | CORS misconfiguration detection (origin reflection, null origin) |
| 5 | **CredentialTester** | Brute-force and password spray testing |
| 6 | **ReportGenerator** | JSON/Markdown report generation with severity ratings |
| 7 | **SensitivePathProber** | Common sensitive file detection (`.env`, `.git`, etc.) |
| 8 | **TechFingerprinter** | Web technology stack identification (WordPress, React, etc.) |
| 9 | **HeaderAuditor** | Security header analysis (CSP, HSTS, X-Frame-Options) |
| 10 | **FormExtractor** | Form structure and input analysis |
| 11 | **APIEnumerator** | API endpoint enumeration from JS bundles |
| 12 | **BypassDetector** | Authentication bypass candidate detection |

---

## Installation

```bash
git clone https://github.com/skappafrost/web-recon-suite.git
cd web-recon-suite
pip install -e .

# With dev dependencies
pip install -e ".[dev]"
```

---

## Quick Start

```bash
# Scan a web application
web-recon scan https://example.com -o report.json

# Generate Markdown report too
web-recon scan https://example.com -o report.json --markdown

# Test CORS configuration
web-recon cors https://api.example.com

# Test CORS on specific endpoint
web-recon cors https://api.example.com -e /api/data

# Brute-force login
web-recon brute https://example.com/login -u admin -p password123,test,admin

# Password spray
web-recon spray https://example.com/login -p Welcome123 -u admin,user,root
```

---

## Architecture

```
web_recon/
├── __init__.py          # Package metadata
├── __main__.py          # python -m web_recon entry
├── cli.py               # Click CLI (scan, cors, brute, spray)
├── core/
│   ├── scanner.py       # WebScanner — main scan orchestration
│   ├── endpoints.py     # EndpointDiscoverer — URL/form extraction
│   └── auth.py          # AuthAnalyzer — auth endpoint detection
├── modules/
│   ├── cors.py          # CORSAnalyzer — misconfiguration testing
│   ├── credentials.py   # CredentialTester — brute/spray
│   └── report.py        # ReportGenerator — JSON/Markdown output
└── utils/
    ├── config.py         # ReconConfig — env-based settings
    └── logger.py         # Structured logging
```

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `WEBRECON_TIMEOUT` | `30` | Request timeout (seconds) |
| `WEBRECON_CONCURRENCY` | `10` | Max concurrent requests |
| `WEBRECON_USER_AGENT` | `NEXUS-WebRecon/1.0` | Custom User-Agent |
| `WEBRECON_OUTPUT_DIR` | `reports` | Report output directory |
| `WEBRECON_VERBOSE` | `false` | Verbose mode |

---

## Development

```bash
pip install -e ".[dev]"
pytest
ruff check web_recon/ tests/
mypy web_recon/ --ignore-missing-imports
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

⭐ **Star this repo** if you find it useful. For questions or collaboration, reach out via [GitHub](https://github.com/skappafrost).
