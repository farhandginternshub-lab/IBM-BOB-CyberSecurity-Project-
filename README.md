# 🛡️ Smart URL Reputation Checker

> **Cybersecurity Project** — An intelligent, internet-based web application that analyses any live URL for phishing, malware, brand impersonation, and other threat indicators, then produces a 0–100 risk score with actionable recommendations.

---

## 📋 Project Description

The **Smart URL Reputation Checker** is a Python-based cybersecurity tool with a premium dark-mode web interface. It uses a multi-layer analysis pipeline to evaluate the safety of any URL. The tool requires a live internet connection: before scoring, it verifies that the URL is actually reachable — fake, typo, or offline URLs are rejected with a clear error message rather than silently returning a misleading zero-risk score.

### Key capabilities

| Feature | Detail |
|---|---|
| **Reachability gate** | Verifies the URL is live before scoring — unreachable URLs are rejected |
| **HTTP status check** | Flags 4xx / 5xx responses; displays status code in results |
| Pattern analysis | 12 independent heuristic checks |
| Shannon entropy | Detects DGA / randomly-generated domains |
| Brand impersonation | Catches typosquatting of 18 major brands |
| Risk scoring | Weighted 0–100 score with 5 severity levels |
| Recommendations | Tailored actionable advice per risk level |
| Premium UI | Glassmorphism dark-mode interface with animated SVG gauge |
| HD Cyber Background | Canvas-rendered node graph, hex grid, scanline, floating glyphs |
| REST API | `/scan` endpoint returns full JSON report |

---

## 🌐 Internet-Based Scanning

The tool now performs a live HTTP request to confirm the URL responds before running any analysis:

| Scenario | Behaviour |
|---|---|
| URL resolves and responds (2xx / 3xx) | Full analysis runs, risk score shown |
| DNS fails / host unreachable | Rejected — **"Connection refused or host unreachable"** |
| Request times out | Rejected — **"Request timed out — server did not respond"** |
| Server returns 4xx / 5xx | Rejected — **"Server returned HTTP 404 — URL is not accessible"** |
| Redirect loop | Rejected — **"Too many redirects — redirect loop detected"** |
| Domain redirects to a different host | Rejected — **"Domain redirects to a different host (…) — likely a parked or squatted domain"** |

This prevents typos, fabricated URLs, and **parked/squatted domains** from ever generating a risk score.

---

## 🧠 Threat Detection Checks

1. **Reachability** — live GET request (not HEAD) before any scoring — blocks unreachable, parked, and squatted domains
2. **HTTP Status Code** — 4xx/5xx flagged and displayed
3. **IP Address as Host** — direct IPs bypass domain reputation
4. **URL Length** — abnormally long URLs often encode payloads
5. **Subdomain Depth** — deeply nested subdomains evade domain checks
6. **Special Characters** — `@`, `%` used for URL deception
7. **Phishing Keywords** — login, verify, secure, paypal, amazon …
8. **Malware Keywords** — download, install, exe, dropper …
9. **Brand Impersonation** — 18 major brands checked
10. **HTTPS / Encryption** — plain HTTP is flagged
11. **Non-Standard Ports** — unexpected ports may indicate C2 traffic
12. **Path Obfuscation** — double encoding, HTML injection in path
13. **Query Parameter Safety** — SQL injection / XSS patterns
14. **Hex Obfuscation** — `0x…` encoding in raw URL
15. **Shannon Entropy** — high entropy → algorithmically generated domain
16. **Suspicious TLD** — `.tk`, `.ml`, `.xyz`, `.pw` and 18 others
17. **DNS Resolution** — non-resolving domains flagged
18. **Redirect Chain** — excessive hops may hide true destination

---

## 🏗️ Architecture

```
┌───────────────────────────────────────────────────────┐
│  Presentation Layer   Flask Web UI + REST API          │
├───────────────────────────────────────────────────────┤
│  Application Layer    URLScanner (orchestrator)        │
│    ├─ HTTPS probe via GET+stream (not HEAD)             │
│    └─ Reachability gate (verify_reachable)              │
│        ├─ Parked-domain redirect detection              │
│        └─ Cross-host redirect → rejected                │
├───────────────────────────────────────────────────────┤
│  Domain / Analysis Layer                               │
│    ├─ PatternAnalyzer   (12 heuristic checks)          │
│    ├─ EntropyAnalyzer   (Shannon entropy / DGA)        │
│    ├─ DomainAnalyzer    (TLD, DNS, reachability,       │
│    │                     redirects)                    │
│    └─ RiskScorer        (weighted aggregation)         │
├───────────────────────────────────────────────────────┤
│  Infrastructure Layer  requests · tldextract · socket  │
└───────────────────────────────────────────────────────┘
```

---

## 🎨 UI Design — Premium Features

The interface uses a fully custom design system with no external UI libraries:

| Component | Design Detail |
|---|---|
| **Background** | HD Canvas — animated node network graph, hex-tile grid shimmer, floating binary/hex glyphs, horizontal scanline sweep, radial vignette — rendered at device pixel ratio |
| **Typography** | Inter (UI) + JetBrains Mono (URLs/code) via Google Fonts |
| **Color system** | Deep space dark (`#05070f`) + cyan/violet/emerald accent palette |
| **Input card** | Glassmorphism (`backdrop-filter: blur`) with focus glow ring |
| **Risk gauge** | Animated SVG half-arc gauge (green → yellow → red) with smooth `stroke-dashoffset` animation |
| **Score bar** | Gradient progress bar with animated fill on every scan |
| **Meta tiles** | Colour-coded `.ok` / `.bad` values, hover lift effect — now includes **HTTP Status** tile |
| **Check grid** | 2-column responsive grid, icon boxes, red tint on flagged rows |
| **Cards** | Staggered slide-up entrance animation on result reveal |
| **Scan spinner** | Dual concentric counter-rotating rings + bouncing dots |
| **Error banner** | Rich multi-line error with bold heading for unreachable URLs |

---

## ⚙️ Technologies Used

| Technology | Purpose |
|---|---|
| Python 3.8+ | Core language |
| Flask 3.x | Web framework & REST API |
| requests | HTTP client — reachability check, redirect chain analysis |
| tldextract | Accurate TLD/subdomain extraction |
| Standard library (`re`, `socket`, `math`, `ipaddress`) | Pattern matching, DNS, entropy |
| HTML5 Canvas 2D API | HD cybersecurity background animation |
| Inter + JetBrains Mono | Google Fonts — premium typography |
| CSS glassmorphism + custom properties | Premium UI design system |

---

## 🚀 Setup & Run Instructions

### Prerequisites

- Python 3.8 or higher
- pip
- Active internet connection (required for live URL scanning)

### 1 — Clone / download the project

```bash
# If using git:
git clone <repository-url>
cd smart-url-reputation-checker

# Or extract the ZIP and cd into the folder
```

### 2 — Install dependencies

```bash
pip install -r requirements.txt
```

### 3 — Run the application

```bash
python StudentName_SmartURLReputationChecker.py
```

### 4 — Open in browser

Navigate to **http://127.0.0.1:5001**

> Port can be overridden: `PORT=8080 python StudentName_SmartURLReputationChecker.py`

---

## 🔌 API Usage

**Endpoint:** `POST /scan`  
**Content-Type:** `application/json`

```bash
curl -X POST http://127.0.0.1:5001/scan \
     -H "Content-Type: application/json" \
     -d '{"url": "http://secure-login.paypa1.tk/verify?id=abc"}'
```

**Successful response (excerpt):**

```json
{
  "url": "http://secure-login.paypa1.tk/verify?id=abc",
  "reachable": true,
  "http_status": 200,
  "domain": "secure-login.paypa1.tk",
  "risk": {
    "score": 72,
    "level": "CRITICAL",
    "color": "#dc2626"
  },
  "recommendations": [
    "Do NOT visit this URL — it shows multiple high-risk indicators.",
    "..."
  ]
}
```

**Unreachable URL response (host unreachable):**

```json
{
  "error": "Connection refused or host unreachable",
  "url": "http://not-a-real-site.fake/login",
  "reachable": false
}
```

**Unreachable URL response (parked/squatted domain):**

```json
{
  "error": "Domain redirects to a different host (parkingcrew.net) — likely a parked or squatted domain",
  "url": "https://www.farhan.in",
  "reachable": false
}
```

**Health check:** `GET /health` → `{"status": "ok"}`

---

## 📊 Risk Score Levels

| Score | Level | Meaning |
|---|---|---|
| 0 | SAFE | No indicators found |
| 1–19 | LOW | Minor indicators — likely safe |
| 20–44 | MEDIUM | Proceed with caution |
| 45–69 | HIGH | Avoid without verification |
| 70–100 | CRITICAL | Do not visit |

> **Note:** A score is only generated for URLs that successfully respond to a live HTTP request. Unreachable, non-existent, or server-error URLs are rejected before scoring.

---

## 📁 File Structure

```
smart-url-reputation-checker/
├── StudentName_SmartURLReputationChecker.py    # Main application
├── requirements.txt                             # Python dependencies
├── README.md                                    # This file
└── StudentName_ProjectReport.docx               # Full project report
```

---

## 📚 Dataset / References

This project uses **no external dataset**. All analysis is performed through:

- Built-in heuristic rules and keyword lists (curated from OWASP, PhishTank, URLhaus research)
- Live HTTP reachability check via the `requests` library
- Live DNS resolution via Python's `socket` module
- Live HTTP redirect checking via the `requests` library
- Shannon entropy computation on domain strings

Reference resources:
- [OWASP Web Security Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PhishTank — Open Phishing Database](https://phishtank.org/)
- [URLhaus — Malware URL Database](https://urlhaus.abuse.ch/)
- [Google Safe Browsing API](https://developers.google.com/safe-browsing)

---

## 👤 Author

**StudentName**  
Cybersecurity Project — IBM SkillsBuild / BOB CS Programme  
Year: 2026

---

## 📄 License

This project is submitted for academic/educational purposes.
