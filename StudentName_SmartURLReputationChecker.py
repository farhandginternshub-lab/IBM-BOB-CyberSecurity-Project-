# Generated from: StudentName_SmartURLReputationChecker.ipynb
# Converted at: 2026-10-23T14:14:41.975Z
# Next step (optional): refactor into modules & generate tests with RunCell
# Quick start: pip install runcell

# # 🛡️ Smart URL Reputation Checker
# **Author:** StudentName  
# **Programme:** IBM SkillsBuild / BOB CS  
# **Version:** 2.0.0 — Premium UI + HD Cybersecurity Background
# 
# ---
# 
# ## What this notebook contains
# This notebook is the complete, final version of the project including:
# - All 5 analysis modules (PatternAnalyzer, EntropyAnalyzer, DomainAnalyzer, RiskScorer, RecommendationEngine)
# - Premium glassmorphism web UI with animated SVG risk gauge
# - HD cybersecurity canvas background (node graph, hex grid, scanline, floating glyphs)
# - Flask REST API with `/scan` and `/health` endpoints
# 
# ## Architecture
# ```
# Presentation Layer  → Flask Web UI + REST API
# Application Layer   → URLScanner (orchestrator)
# Domain Layer        → PatternAnalyzer · EntropyAnalyzer · DomainAnalyzer · RiskScorer
# Infrastructure      → requests · tldextract · socket · ipaddress
# ```
# 
# ## How to run
# 1. Run Cell 1 to install dependencies
# 2. Run Cells 2–9 to define all classes
# 3. Run Cell 10 for a quick demo scan (no server)
# 4. Run Cell 11 to start the web server → open http://127.0.0.1:5001


import subprocess, sys
subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'flask', 'requests', 'tldextract'])
print('All dependencies installed.')

# ## Cell 2 — Imports


# ── Standard library ───────────────────────────────────────────────────────
import re
import math
import socket
import string
import hashlib
import datetime
import ipaddress
from urllib.parse import urlparse, parse_qs, unquote

# ── Third-party ────────────────────────────────────────────────────────────
import requests
import tldextract
from flask import Flask, render_template_string, request, jsonify

# ## Cell 3 — Threat Intelligence Lists


# ---------------------------------------------------------------------------
# Suspicious keyword lists
# ---------------------------------------------------------------------------
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "secure", "account", "update",
    "verify", "banking", "paypal", "amazon", "google", "apple",
    "microsoft", "netflix", "ebay", "password", "credential",
    "confirm", "invoice", "payment", "wallet", "crypto", "recover",
    "suspended", "urgent", "limited", "click", "free", "prize",
    "winner", "congratulations", "lucky", "reward",
]

MALWARE_KEYWORDS = [
    "download", "install", "setup", "exe", "bat", "cmd", "ps1",
    "vbs", "jar", "apk", "dmg", "pkg", "msi", "run", "dropper",
    "payload", "exploit", "shell", "backdoor", "rootkit", "trojan",
    "ransomware", "keylogger", "spyware",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq", ".top", ".xyz", ".pw",
    ".cc", ".ws", ".biz", ".info", ".click", ".link", ".online",
    ".site", ".web", ".tech", ".space", ".club", ".vip",
}

BRAND_NAMES = [
    "paypal", "google", "amazon", "microsoft", "apple", "facebook",
    "instagram", "twitter", "netflix", "ebay", "dropbox", "linkedin",
    "github", "bankofamerica", "wellsfargo", "chase", "citibank",
]

SAFE_TLDS = {".com", ".org", ".net", ".edu", ".gov", ".mil"}

# ## Cell 4 — PatternAnalyzer (12 heuristic checks)


class PatternAnalyzer:
    """Performs pattern-based analysis on a parsed URL."""

    def __init__(self, parsed_url: urlparse, raw_url: str):
        self.parsed = parsed_url
        self.raw = raw_url
        self.full_lower = raw_url.lower()
        self.domain_lower = (parsed_url.netloc or "").lower()

    # ---- individual checks ------------------------------------------------

    def check_ip_address(self) -> dict:
        """Detects raw IP address in host field instead of a domain name."""
        host = self.parsed.hostname or ""
        try:
            ipaddress.ip_address(host)
            return {"flag": True, "detail": f"Host is a raw IP address ({host})"}
        except ValueError:
            return {"flag": False, "detail": "Host is a proper domain name"}

    def check_url_length(self) -> dict:
        length = len(self.raw)
        if length > 100:
            return {"flag": True, "detail": f"Unusually long URL ({length} chars)"}
        return {"flag": False, "detail": f"URL length is acceptable ({length} chars)"}

    def check_subdomain_depth(self) -> dict:
        host = self.parsed.hostname or ""
        parts = host.split(".")
        depth = max(0, len(parts) - 2)
        if depth >= 3:
            return {"flag": True, "detail": f"Deep subdomain nesting detected ({depth} levels)"}
        return {"flag": False, "detail": f"Subdomain depth is normal ({depth} levels)"}

    def check_special_chars(self) -> dict:
        url_part = self.parsed.netloc + (self.parsed.path or "")
        suspicious = re.findall(r"[@%]", url_part)
        if suspicious:
            return {"flag": True, "detail": f"Suspicious characters found: {set(suspicious)}"}
        return {"flag": False, "detail": "No suspicious special characters found"}

    def check_phishing_keywords(self) -> dict:
        hits = [kw for kw in PHISHING_KEYWORDS if kw in self.full_lower]
        if hits:
            return {"flag": True, "detail": f"Phishing keywords detected: {hits[:5]}"}
        return {"flag": False, "detail": "No phishing keywords found"}

    def check_malware_keywords(self) -> dict:
        hits = [kw for kw in MALWARE_KEYWORDS if kw in self.full_lower]
        if hits:
            return {"flag": True, "detail": f"Malware-related keywords: {hits[:5]}"}
        return {"flag": False, "detail": "No malware-related keywords found"}

    def check_brand_impersonation(self) -> dict:
        extracted = tldextract.extract(self.domain_lower)
        domain_main = extracted.domain
        for brand in BRAND_NAMES:
            if brand in self.domain_lower and brand != domain_main:
                return {
                    "flag": True,
                    "detail": f"Possible brand impersonation of '{brand}' in domain",
                }
        return {"flag": False, "detail": "No obvious brand impersonation detected"}

    def check_https(self) -> dict:
        if self.parsed.scheme == "https":
            return {"flag": False, "detail": "Connection uses HTTPS (encrypted)"}
        return {"flag": True, "detail": "Connection uses HTTP (unencrypted)"}

    def check_port(self) -> dict:
        port = self.parsed.port
        if port and port not in (80, 443):
            return {"flag": True, "detail": f"Non-standard port in use: {port}"}
        return {"flag": False, "detail": "Standard port (or none specified)"}

    def check_path_obfuscation(self) -> dict:
        path = self.parsed.path or ""
        decoded = unquote(path)
        double_enc = re.findall(r"%25[0-9a-fA-F]{2}", path)
        if double_enc:
            return {"flag": True, "detail": "Double URL-encoding detected in path"}
        if len(decoded) != len(path) and any(c in decoded for c in ["<", ">", "'"]):
            return {"flag": True, "detail": "URL-encoded HTML/script injection attempts"}
        return {"flag": False, "detail": "No path obfuscation detected"}

    def check_query_params(self) -> dict:
        query = self.parsed.query or ""
        params = parse_qs(query)
        if len(params) > 8:
            return {"flag": True, "detail": f"Excessive query parameters ({len(params)})"}
        for key, values in params.items():
            for val in values:
                if re.search(r"(<script|javascript:|on\w+=|union\s+select)", val, re.I):
                    return {"flag": True, "detail": f"Injection pattern in parameter '{key}'"}
        return {"flag": False, "detail": "Query parameters appear normal"}

    def check_hex_obfuscation(self) -> dict:
        if re.search(r"0x[0-9a-fA-F]{4,}", self.raw):
            return {"flag": True, "detail": "Hexadecimal obfuscation detected in URL"}
        return {"flag": False, "detail": "No hexadecimal obfuscation detected"}

    def run_all(self) -> list[dict]:
        checks = [
            ("IP Address Host",         self.check_ip_address()),
            ("URL Length",              self.check_url_length()),
            ("Subdomain Depth",         self.check_subdomain_depth()),
            ("Special Characters",      self.check_special_chars()),
            ("Phishing Keywords",       self.check_phishing_keywords()),
            ("Malware Keywords",        self.check_malware_keywords()),
            ("Brand Impersonation",     self.check_brand_impersonation()),
            ("HTTPS / Encryption",      self.check_https()),
            ("Non-Standard Port",       self.check_port()),
            ("Path Obfuscation",        self.check_path_obfuscation()),
            ("Query Parameter Safety",  self.check_query_params()),
            ("Hex Obfuscation",         self.check_hex_obfuscation()),
        ]
        return [{"name": name, **result} for name, result in checks]


# ---------------------------------------------------------------------------
# EntropyAnalyzer – detects randomly-generated / DGA-style domains
# ---------------------------------------------------------------------------

# ## Cell 5 — EntropyAnalyzer (Shannon entropy / DGA detection)


class EntropyAnalyzer:
    """Calculates Shannon entropy to detect algorithmically-generated domains."""

    def calculate(self, text: str) -> float:
        if not text:
            return 0.0
        freq = {c: text.count(c) / len(text) for c in set(text)}
        return -sum(p * math.log2(p) for p in freq.values())

    def analyze_domain(self, domain: str) -> dict:
        entropy = self.calculate(domain)
        digit_ratio = sum(c.isdigit() for c in domain) / max(len(domain), 1)
        consonant_cluster = bool(re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", domain, re.I))

        flags = []
        if entropy > 3.8:
            flags.append(f"High entropy ({entropy:.2f}) suggests random generation")
        if digit_ratio > 0.35:
            flags.append(f"High digit ratio ({digit_ratio:.0%})")
        if consonant_cluster:
            flags.append("Unusual consonant cluster (possible DGA domain)")

        return {
            "entropy": round(entropy, 2),
            "digit_ratio": round(digit_ratio, 2),
            "flagged": bool(flags),
            "flags": flags,
        }


# ---------------------------------------------------------------------------
# DomainAnalyzer – TLD, age, DNS
# ---------------------------------------------------------------------------

# ## Cell 6 — DomainAnalyzer (TLD · DNS · Redirects)


class DomainAnalyzer:
    """Analyses the domain component of the URL."""

    def check_tld(self, suffix: str) -> dict:
        tld = f".{suffix}" if suffix else ""
        if tld in SUSPICIOUS_TLDS:
            return {"flagged": True, "detail": f"Suspicious TLD: '{tld}'"}
        if tld in SAFE_TLDS:
            return {"flagged": False, "detail": f"Trusted TLD: '{tld}'"}
        return {"flagged": False, "detail": f"TLD '{tld}' is not in suspicious list"}

    def resolve_dns(self, hostname: str) -> dict:
        try:
            ip = socket.gethostbyname(hostname)
            return {"resolved": True, "ip": ip, "flagged": False}
        except socket.gaierror:
            return {"resolved": False, "ip": None, "flagged": True,
                    "detail": "Domain does not resolve — possibly inactive or fake"}

    def verify_reachable(self, url: str) -> dict:
        """
        Performs a live HTTP request to confirm the URL is actually reachable.
        Returns a dict with keys:
          reachable  – bool
          status_code – int or None
          error      – str or None (human-readable failure reason)
        """
        try:
            resp = requests.get(
                url,
                allow_redirects=True,
                timeout=8,
                headers={"User-Agent": "Mozilla/5.0 (SmartURLChecker/1.0)"},
                stream=True,   # don't download the body
            )
            resp.close()
            if resp.status_code >= 400:
                return {
                    "reachable": False,
                    "status_code": resp.status_code,
                    "error": f"Server returned HTTP {resp.status_code} — URL is not accessible",
                }
            # ── Parked-domain detection ──────────────────────────────────────
            # If the chain of redirects landed on a completely different
            # registrar / parking host, the domain is likely parked/squatted.
            if resp.history:
                original_host = urlparse(url).hostname or ""
                final_host    = urlparse(str(resp.url)).hostname or ""
                # Strip leading "www." for comparison
                orig_bare  = original_host.removeprefix("www.")
                final_bare = final_host.removeprefix("www.")
                if orig_bare and final_bare and orig_bare != final_bare:
                    return {
                        "reachable": False,
                        "status_code": resp.status_code,
                        "error": (
                            f"Domain redirects to a different host ({final_host}) — "
                            "likely a parked or squatted domain"
                        ),
                    }
            return {"reachable": True, "status_code": resp.status_code, "error": None}
        except requests.exceptions.ConnectionError:
            return {"reachable": False, "status_code": None,
                    "error": "Connection refused or host unreachable"}
        except requests.exceptions.Timeout:
            return {"reachable": False, "status_code": None,
                    "error": "Request timed out — server did not respond"}
        except requests.exceptions.TooManyRedirects:
            return {"reachable": False, "status_code": None,
                    "error": "Too many redirects — redirect loop detected"}
        except Exception as exc:
            return {"reachable": False, "status_code": None,
                    "error": f"URL is not reachable: {exc}"}

    def check_redirects(self, url: str) -> dict:
        try:
            # Use GET+stream — HEAD is frequently blocked by servers
            resp = requests.get(
                url, allow_redirects=True, timeout=5,
                headers={"User-Agent": "Mozilla/5.0 (SmartURLChecker/1.0)"},
                stream=True,
            )
            resp.close()
            hops = len(resp.history)
            if hops > 2:
                return {"flagged": True, "hops": hops,
                        "detail": f"Excessive redirects ({hops}) may hide destination"}
            return {"flagged": False, "hops": hops,
                    "detail": f"Redirect chain is acceptable ({hops} hops)"}
        except requests.exceptions.TooManyRedirects:
            return {"flagged": True, "hops": -1,
                    "detail": "Redirect loop detected — destination is hidden"}
        except Exception as exc:
            return {"flagged": True, "hops": 0,
                    "detail": f"Redirect check failed (connection error): {exc}"}


# ---------------------------------------------------------------------------
# RiskScorer – aggregates findings into a single 0-100 score
# ---------------------------------------------------------------------------

# ## Cell 7 — RiskScorer + RecommendationEngine


class RiskScorer:
    """
    Weights:
        Critical  = 15 pts  (IP host, brand impersonation, injection)
        High      = 10 pts  (HTTP, DGA domain, suspicious TLD, DNS fail)
        Medium    =  7 pts  (phishing keywords, malware keywords, hex obf, redirects)
        Low       =  3 pts  (long URL, deep subdomains, port, path obfuscation, params)
    """

    CRITICAL = 15
    HIGH     = 10
    MEDIUM   =  7
    LOW      =  3

    def compute(self, pattern_checks, entropy_result, tld_result,
                dns_result, redirect_result) -> dict:

        score = 0
        reasons = []

        # --- Pattern checks ---
        for chk in pattern_checks:
            if not chk["flag"]:
                continue
            name = chk["name"]
            if name in ("Brand Impersonation", "Query Parameter Safety"):
                score += self.CRITICAL
            elif name in ("HTTPS / Encryption", "IP Address Host"):
                score += self.HIGH
            elif name in ("Phishing Keywords", "Malware Keywords", "Hex Obfuscation"):
                score += self.MEDIUM
            else:
                score += self.LOW
            reasons.append(chk["detail"])

        # --- Entropy / DGA ---
        if entropy_result["flagged"]:
            score += self.HIGH
            reasons.extend(entropy_result["flags"])

        # --- TLD ---
        if tld_result["flagged"]:
            score += self.HIGH
            reasons.append(tld_result["detail"])

        # --- DNS ---
        if dns_result.get("flagged"):
            score += self.HIGH
            reasons.append(dns_result.get("detail", "DNS resolution failed"))

        # --- Redirects ---
        if redirect_result.get("flagged"):
            score += self.MEDIUM
            reasons.append(redirect_result.get("detail", "Excessive redirects"))

        score = min(score, 100)
        level, color = self._level(score)

        return {
            "score": score,
            "level": level,
            "color": color,
            "reasons": reasons,
        }

    @staticmethod
    def _level(score: int) -> tuple[str, str]:
        if score >= 70:
            return "CRITICAL", "#dc2626"
        elif score >= 45:
            return "HIGH", "#ea580c"
        elif score >= 20:
            return "MEDIUM", "#d97706"
        elif score > 0:
            return "LOW", "#16a34a"
        return "SAFE", "#15803d"


# ---------------------------------------------------------------------------
# RecommendationEngine – generates actionable advice
# ---------------------------------------------------------------------------


class RecommendationEngine:
    """Produces human-readable recommendations based on risk score and flags."""

    ADVICE = {
        "CRITICAL": [
            "🚨 Do NOT visit this URL — it shows multiple high-risk indicators.",
            "Block this URL in your firewall or DNS filter immediately.",
            "Report this URL to a threat intelligence platform (e.g., VirusTotal, PhishTank).",
            "If you have already visited it, change your passwords and scan your device.",
        ],
        "HIGH": [
            "⚠️  Avoid clicking this URL without further verification.",
            "Use a sandbox environment (e.g., urlscan.io) to inspect it safely.",
            "Check the domain WHOIS registration date — new domains are riskier.",
            "Enable multi-factor authentication on accounts that may be targeted.",
        ],
        "MEDIUM": [
            "🔍 Proceed with caution — verify the source before interacting.",
            "Hover over hyperlinks to inspect the actual destination URL.",
            "Do not enter credentials or personal information on this page.",
            "Consider scanning with VirusTotal or any AV browser extension.",
        ],
        "LOW": [
            "ℹ️  Minor indicators detected — the URL may still be legitimate.",
            "Ensure the website uses HTTPS before submitting any data.",
            "Look for spelling errors or unexpected domains in the address bar.",
        ],
        "SAFE": [
            "✅ No suspicious indicators found — URL appears safe.",
            "Always keep your browser and OS updated for best protection.",
            "Continue to practice safe browsing habits.",
        ],
    }

    def get(self, level: str) -> list[str]:
        return self.ADVICE.get(level, self.ADVICE["SAFE"])

# ## Cell 8 — URLScanner (Application Layer Orchestrator)


class URLScanner:
    """
    Orchestrates the full analysis pipeline.

    Usage
    -----
        scanner = URLScanner()
        result  = scanner.scan("http://secure-login.paypa1.tk/verify?id=abc")
        print(result)
    """

    def __init__(self):
        self.entropy_analyzer     = EntropyAnalyzer()
        self.domain_analyzer      = DomainAnalyzer()
        self.risk_scorer          = RiskScorer()
        self.recommendation_engine = RecommendationEngine()

    def scan(self, raw_url: str) -> dict:
        """Run all checks and return a structured report."""
        raw_url = raw_url.strip()
        if not raw_url.startswith(("http://", "https://")):
            # Probe whether the site supports HTTPS before assuming HTTP.
            # A real HTTPS site typed without a scheme (e.g. "cbse.gov.in")
            # must not be incorrectly flagged as unencrypted.
            https_candidate = "https://" + raw_url
            try:
                # Use GET+stream (not HEAD) — many servers block HEAD requests
                probe = requests.get(
                    https_candidate, allow_redirects=True, timeout=5,
                    headers={"User-Agent": "Mozilla/5.0 (SmartURLChecker/1.0)"},
                    stream=True,
                )
                probe.close()
                raw_url = https_candidate  # Any response means HTTPS is active
            except Exception:
                raw_url = "http://" + raw_url  # HTTPS probe failed — fall back

        # ── Reachability gate ───────────────────────────────────────────────
        # Only score URLs that actually respond on the internet.
        # Fake / typo / offline URLs are rejected with a clear error message
        # instead of silently returning a misleading 0-risk score.
        reachability = self.domain_analyzer.verify_reachable(raw_url)
        if not reachability["reachable"]:
            return {
                "error": reachability["error"],
                "url": raw_url,
                "reachable": False,
            }

        parsed = urlparse(raw_url)
        extracted = tldextract.extract(raw_url)

        # Pattern checks
        pattern_analyzer = PatternAnalyzer(parsed, raw_url)
        pattern_checks   = pattern_analyzer.run_all()

        # Entropy / DGA
        entropy_result = self.entropy_analyzer.analyze_domain(
            extracted.domain + ("." + extracted.suffix if extracted.suffix else "")
        )

        # TLD check
        tld_result = self.domain_analyzer.check_tld(extracted.suffix)

        # DNS
        hostname = parsed.hostname or ""
        dns_result = self.domain_analyzer.resolve_dns(hostname)

        # Redirect check
        redirect_result = self.domain_analyzer.check_redirects(raw_url)

        # Scoring
        risk = self.risk_scorer.compute(
            pattern_checks, entropy_result, tld_result, dns_result, redirect_result
        )

        # Recommendations
        recommendations = self.recommendation_engine.get(risk["level"])

        return {
            "url":             raw_url,
            "scanned_at":      datetime.datetime.utcnow().isoformat() + "Z",
            "reachable":       True,
            "http_status":     reachability.get("status_code"),
            "domain":          hostname,
            "tld":             extracted.suffix,
            "ip_address":      dns_result.get("ip"),
            "pattern_checks":  pattern_checks,
            "entropy":         entropy_result,
            "tld_analysis":    tld_result,
            "dns":             dns_result,
            "redirects":       redirect_result,
            "risk":            risk,
            "recommendations": recommendations,
        }

scanner = URLScanner()
print('URLScanner ready.')

# ## Cell 9 — HTML Template (Premium UI + HD Canvas Background)
# 
# > This cell defines the complete self-contained frontend:
# > - Glassmorphism dark UI (Inter + JetBrains Mono fonts)
# > - Animated SVG half-arc risk gauge
# > - Canvas background: node network graph, hex grid, floating glyphs, scanline sweep, radial vignette
# > - REST API async fetch with staggered card animations


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>ShieldScan — Smart URL Reputation Checker</title>
<!-- Fonts: preconnect for speed, loaded as <link> not @import to avoid blocking CSS -->
<link rel="preconnect" href="https://fonts.googleapis.com" crossorigin>
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600&display=swap">
<style>
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

:root {
  --bg:        #05070f;
  --surface:   rgba(255,255,255,0.04);
  --glass:     rgba(255,255,255,0.06);
  --glass-hi:  rgba(255,255,255,0.09);
  --border:    rgba(255,255,255,0.08);
  --border-hi: rgba(99,179,237,0.35);
  --text:      #f0f4ff;
  --muted:     #6b7fa3;
  --dim:       #3a4a6b;
  --accent:    #63b3ed;
  --accent2:   #a78bfa;
  --green:     #34d399;
  --yellow:    #fbbf24;
  --orange:    #fb923c;
  --red:       #f87171;
  --safe-glow:   0 0 32px rgba(52,211,153,0.25);
  --low-glow:    0 0 32px rgba(52,211,153,0.2);
  --med-glow:    0 0 32px rgba(251,191,36,0.25);
  --high-glow:   0 0 32px rgba(251,146,60,0.3);
  --crit-glow:   0 0 40px rgba(248,113,113,0.35);
}

/* ── Base ─────────────────────────────────────────────────────────────── */
html { scroll-behavior: smooth; }
body {
  background: var(--bg);
  color: var(--text);
  font-family: 'Inter', system-ui, sans-serif;
  min-height: 100vh;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 0 1rem 4rem;
  overflow-x: hidden;
}

/* ── Canvas background ──────────────────────────────────────────────────── */
#bg-canvas {
  position: fixed; inset: 0; z-index: 0;
  width: 100%; height: 100%;
  pointer-events: none;
}

/* ── Hero header ──────────────────────────────────────────────────────── */
.hero {
  position: relative; z-index: 1;
  width: 100%; max-width: 860px;
  text-align: center;
  padding: 4.5rem 1rem 2.5rem;
}
.hero-badge {
  display: inline-flex; align-items: center; gap: .5rem;
  background: rgba(99,179,237,0.08);
  border: 1px solid rgba(99,179,237,0.2);
  border-radius: 999px;
  padding: .3rem 1rem;
  font-size: .72rem; font-weight: 600;
  color: var(--accent); letter-spacing: .12em; text-transform: uppercase;
  margin-bottom: 1.5rem;
}
.hero-badge-dot {
  width: 6px; height: 6px; border-radius: 50%;
  background: var(--accent);
  box-shadow: 0 0 8px var(--accent);
  animation: pulse-dot 2s ease-in-out infinite;
}
@keyframes pulse-dot {
  0%,100% { opacity:1; transform:scale(1); }
  50%      { opacity:.4; transform:scale(.7); }
}
.hero h1 {
  font-size: clamp(2rem, 5vw, 3.2rem);
  font-weight: 900;
  letter-spacing: -.03em;
  line-height: 1.1;
  background: linear-gradient(135deg, #f0f4ff 30%, #63b3ed 70%, #a78bfa 100%);
  -webkit-background-clip: text; -webkit-text-fill-color: transparent;
  background-clip: text;
  margin-bottom: .75rem;
}
.hero-sub {
  color: var(--muted); font-size: 1rem; font-weight: 400;
  max-width: 480px; margin: 0 auto 2.5rem; line-height: 1.65;
}

/* ── Scan input card ─────────────────────────────────────────────────── */
.scan-card {
  position: relative; z-index: 1;
  width: 100%; max-width: 860px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 1.25rem;
  padding: 1.75rem 2rem;
  margin-bottom: 1rem;
  backdrop-filter: blur(16px);
  transition: border-color .3s;
}
.scan-card:focus-within {
  border-color: var(--border-hi);
  box-shadow: 0 0 0 1px rgba(99,179,237,0.15), 0 8px 40px rgba(0,0,0,.4);
}
.input-wrap {
  display: flex; gap: .75rem; align-items: stretch;
}
.url-input-container {
  flex: 1; position: relative;
}
.url-prefix {
  position: absolute; left: 1rem; top: 50%; transform: translateY(-50%);
  color: var(--dim); font-size: .85rem; font-family: 'JetBrains Mono', monospace;
  pointer-events: none; user-select: none;
}
#urlInput {
  width: 100%; padding: .9rem 1rem .9rem 2.6rem;
  background: rgba(255,255,255,0.05);
  border: 1px solid var(--border);
  border-radius: .875rem;
  color: var(--text);
  font-size: .95rem; font-family: 'JetBrains Mono', monospace;
  outline: none;
  transition: border-color .2s, background .2s, box-shadow .2s;
}
#urlInput::placeholder { color: var(--dim); font-size: .85rem; }
#urlInput:focus {
  border-color: var(--border-hi);
  background: rgba(99,179,237,0.05);
  box-shadow: 0 0 0 3px rgba(99,179,237,0.1);
}
#scanBtn {
  display: flex; align-items: center; gap: .55rem;
  padding: .9rem 1.75rem;
  background: linear-gradient(135deg, #63b3ed, #a78bfa);
  color: #05070f;
  border: none; border-radius: .875rem;
  font-weight: 700; font-size: .95rem; font-family: 'Inter', sans-serif;
  cursor: pointer; white-space: nowrap;
  transition: opacity .2s, transform .15s, box-shadow .2s;
  box-shadow: 0 4px 20px rgba(99,179,237,0.3);
}
#scanBtn:hover:not(:disabled) {
  opacity: .92; transform: translateY(-1px);
  box-shadow: 0 6px 28px rgba(99,179,237,0.4);
}
#scanBtn:active:not(:disabled) { transform: translateY(0); }
#scanBtn:disabled { opacity: .45; cursor: not-allowed; transform: none; }
.btn-icon { font-size: 1rem; }
#error-msg {
  color: var(--red); font-size: .85rem; margin-top: .75rem;
  display: none; padding: .75rem 1rem;
  background: rgba(248,113,113,0.08);
  border: 1px solid rgba(248,113,113,0.2);
  border-radius: .625rem;
  line-height: 1.65;
}
#error-msg strong { display: block; margin-bottom: .25rem; font-size: .9rem; }

/* ── Scanning animation overlay ──────────────────────────────────────── */
#spinner {
  display: none; position: relative; z-index: 1;
  width: 100%; max-width: 860px;
  text-align: center; padding: 3rem 1rem;
}
.scan-anim {
  display: inline-flex; flex-direction: column; align-items: center; gap: 1.25rem;
}
.scan-ring-wrap {
  position: relative; width: 72px; height: 72px;
}
.scan-ring {
  width: 72px; height: 72px;
  border: 2px solid rgba(99,179,237,0.1);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: spin .9s linear infinite;
}
.scan-ring-inner {
  position: absolute; top: 12px; left: 12px;
  width: 48px; height: 48px;
  border: 2px solid rgba(167,139,250,0.1);
  border-top-color: var(--accent2);
  border-radius: 50%;
  animation: spin 1.4s linear infinite reverse;
}
@keyframes spin { to { transform: rotate(360deg); } }
.scan-dots span {
  display: inline-block; width: 6px; height: 6px;
  background: var(--accent); border-radius: 50%; margin: 0 3px;
  animation: bounce-dot .9s ease-in-out infinite;
}
.scan-dots span:nth-child(2) { animation-delay: .15s; }
.scan-dots span:nth-child(3) { animation-delay: .30s; }
@keyframes bounce-dot {
  0%,80%,100% { transform: scale(.6); opacity:.4; }
  40%          { transform: scale(1);  opacity:1; }
}
.scan-label { color: var(--muted); font-size: .9rem; letter-spacing: .04em; }

/* ── Generic glass card ──────────────────────────────────────────────── */
.card {
  position: relative; z-index: 1;
  width: 100%; max-width: 860px;
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 1.25rem;
  padding: 2rem;
  margin-bottom: 1.25rem;
  backdrop-filter: blur(16px);
  animation: card-in .45s cubic-bezier(.22,1,.36,1) both;
}
@keyframes card-in {
  from { opacity:0; transform:translateY(18px); }
  to   { opacity:1; transform:translateY(0); }
}
.card:nth-child(2) { animation-delay: .08s; }
.card:nth-child(3) { animation-delay: .16s; }
.card:nth-child(4) { animation-delay: .24s; }

.section-title {
  display: flex; align-items: center; gap: .6rem;
  font-size: .72rem; font-weight: 700;
  color: var(--muted); letter-spacing: .12em; text-transform: uppercase;
  margin-bottom: 1.25rem;
}
.section-title::before {
  content: '';
  display: inline-block; width: 3px; height: 14px;
  background: linear-gradient(to bottom, var(--accent), var(--accent2));
  border-radius: 2px; flex-shrink: 0;
}

/* ── Score gauge card ────────────────────────────────────────────────── */
#results { display:none; }
.score-card {
  display: flex; align-items: center; gap: 2.5rem;
  flex-wrap: wrap;
}
.gauge-wrap {
  flex-shrink: 0; position: relative;
  width: 160px; height: 100px; overflow: visible;
}
.gauge-wrap svg { overflow: visible; }
#gaugeArc {
  transition: stroke-dashoffset 1s cubic-bezier(.4,0,.2,1),
              stroke .6s ease;
}
.gauge-center {
  position: absolute; bottom: 0; left: 50%; transform: translateX(-50%);
  text-align: center; pointer-events: none;
}
#scoreNum {
  font-size: 2.6rem; font-weight: 900; line-height: 1;
  font-family: 'Inter', sans-serif;
  transition: color .6s ease;
}
#scoreLevel {
  font-size: .7rem; font-weight: 700; letter-spacing: .15em;
  color: var(--muted); text-transform: uppercase;
  margin-top: .2rem;
  transition: color .6s ease;
}
.score-meta { flex: 1; min-width: 200px; }
.score-desc {
  font-size: 1.05rem; font-weight: 600; margin-bottom: .4rem;
}
.score-sub { font-size: .85rem; color: var(--muted); line-height: 1.6; }
.score-bar-wrap {
  margin-top: 1rem; height: 5px;
  background: rgba(255,255,255,0.06); border-radius: 999px; overflow: hidden;
}
.score-bar {
  height: 100%; border-radius: 999px;
  background: linear-gradient(90deg, var(--green), var(--yellow), var(--red));
  transition: width 1s cubic-bezier(.4,0,.2,1);
}
.score-ticks {
  display: flex; justify-content: space-between;
  font-size: .67rem; color: var(--dim); margin-top: .35rem;
}

/* ── Meta grid ───────────────────────────────────────────────────────── */
.meta-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(180px, 1fr));
  gap: .75rem;
}
.meta-item {
  background: var(--glass);
  border: 1px solid var(--border);
  border-radius: .875rem;
  padding: .9rem 1rem;
  transition: border-color .2s, background .2s;
}
.meta-item:hover {
  background: var(--glass-hi);
  border-color: rgba(99,179,237,0.2);
}
.meta-label {
  font-size: .67rem; font-weight: 600; text-transform: uppercase;
  letter-spacing: .1em; color: var(--dim); margin-bottom: .35rem;
}
.meta-val {
  font-size: .88rem; font-family: 'JetBrains Mono', monospace;
  color: var(--text); word-break: break-all; line-height: 1.4;
}
.meta-val.ok  { color: var(--green); }
.meta-val.bad { color: var(--red); }

/* ── Check grid ──────────────────────────────────────────────────────── */
.checks-layout {
  display: grid; grid-template-columns: 1fr 1fr; gap: .65rem;
}
@media (max-width: 560px) { .checks-layout { grid-template-columns: 1fr; } }
.check-item {
  display: flex; align-items: flex-start; gap: .75rem;
  padding: .8rem 1rem;
  background: var(--glass);
  border: 1px solid var(--border);
  border-radius: .875rem;
  transition: border-color .2s, background .2s, transform .2s;
}
.check-item:hover { background: var(--glass-hi); transform: translateY(-1px); }
.check-item.pass { border-left: 2px solid var(--green); }
.check-item.fail { border-left: 2px solid var(--red); background: rgba(248,113,113,0.05); }
.check-item.fail:hover { background: rgba(248,113,113,0.08); }
.check-icon-box {
  width: 28px; height: 28px; border-radius: .5rem; flex-shrink: 0;
  display: flex; align-items: center; justify-content: center; font-size: .85rem;
  margin-top: .05rem;
}
.pass .check-icon-box { background: rgba(52,211,153,0.12); }
.fail .check-icon-box { background: rgba(248,113,113,0.12); }
.check-text { flex: 1; min-width: 0; }
.check-name { font-size: .82rem; font-weight: 600; color: var(--text); }
.check-detail { font-size: .75rem; color: var(--muted); margin-top: .2rem; line-height: 1.45; }

/* ── Stats bar ───────────────────────────────────────────────────────── */
.stats-row {
  display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.25rem;
}
.stat-pill {
  display: flex; align-items: center; gap: .45rem;
  padding: .35rem .85rem;
  border-radius: 999px; font-size: .78rem; font-weight: 600;
}
.stat-pill.pass-pill { background: rgba(52,211,153,0.1); color: var(--green); border: 1px solid rgba(52,211,153,0.2); }
.stat-pill.fail-pill { background: rgba(248,113,113,0.1); color: var(--red);   border: 1px solid rgba(248,113,113,0.2); }
.stat-dot { width: 6px; height: 6px; border-radius: 50%; flex-shrink:0; }
.pass-pill .stat-dot { background: var(--green); }
.fail-pill .stat-dot { background: var(--red); }

/* ── Recommendations ─────────────────────────────────────────────────── */
.rec-list { list-style: none; display: grid; gap: .65rem; }
.rec-list li {
  display: flex; align-items: flex-start; gap: .85rem;
  background: var(--glass);
  border: 1px solid var(--border);
  border-radius: .875rem;
  padding: .9rem 1.1rem;
  font-size: .88rem; line-height: 1.55; color: var(--text);
  transition: border-color .2s, background .2s;
}
.rec-list li:hover { background: var(--glass-hi); border-color: rgba(99,179,237,0.2); }
.rec-num {
  width: 22px; height: 22px; border-radius: 50%; flex-shrink: 0;
  background: rgba(99,179,237,0.12); color: var(--accent);
  font-size: .7rem; font-weight: 700;
  display: flex; align-items: center; justify-content: center;
  margin-top: .1rem;
}

/* ── Footer ──────────────────────────────────────────────────────────── */
footer {
  position: relative; z-index: 1;
  margin-top: 2rem; padding-top: 2rem;
  border-top: 1px solid var(--border);
  color: var(--dim); font-size: .75rem; text-align: center;
  width: 100%; max-width: 860px;
  line-height: 1.7;
}
footer a { color: var(--accent); text-decoration: none; }
footer a:hover { text-decoration: underline; }

/* ── Scrollbar ───────────────────────────────────────────────────────── */
::-webkit-scrollbar { width: 6px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: rgba(255,255,255,0.1); border-radius: 3px; }
</style>
</head>
<body>
<canvas id="bg-canvas"></canvas>

<!-- ═══ HERO ════════════════════════════════════════════════════════════ -->
<div class="hero">
  <div class="hero-badge">
    <span class="hero-badge-dot"></span>
    Cybersecurity Tool
  </div>
  <h1>Smart URL<br>Reputation Checker</h1>
  <p class="hero-sub">
    Paste any link and get an instant AI-assisted risk score,
    threat analysis, and actionable recommendations — no API key required.
  </p>
</div>

<!-- ═══ SCAN CARD ═══════════════════════════════════════════════════════ -->
<div class="scan-card">
  <div class="input-wrap">
    <div class="url-input-container">
      <span class="url-prefix">URL</span>
      <input type="text" id="urlInput"
             placeholder="https://example.com/page?id=1"
             autocomplete="off" spellcheck="false"/>
    </div>
    <button id="scanBtn" onclick="scanURL()">
      <span class="btn-icon">⚡</span> Analyse
    </button>
  </div>
  <div id="error-msg"></div>
</div>

<!-- ═══ SPINNER ══════════════════════════════════════════════════════════ -->
<div id="spinner">
  <div class="scan-anim">
    <div class="scan-ring-wrap">
      <div class="scan-ring"></div>
      <div class="scan-ring-inner"></div>
    </div>
    <div class="scan-dots">
      <span></span><span></span><span></span>
    </div>
    <div class="scan-label">Analysing URL threat vectors…</div>
  </div>
</div>

<!-- ═══ RESULTS ══════════════════════════════════════════════════════════ -->
<div id="results">

  <!-- Score card -->
  <div class="card" id="scoreCard">
    <div class="section-title">Risk Assessment</div>
    <div class="score-card">
      <!-- SVG Gauge -->
      <div class="gauge-wrap">
        <svg width="160" height="100" viewBox="0 0 160 100">
          <defs>
            <linearGradient id="gaugeGrad" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%"   stop-color="#34d399"/>
              <stop offset="50%"  stop-color="#fbbf24"/>
              <stop offset="100%" stop-color="#f87171"/>
            </linearGradient>
          </defs>
          <!-- Track -->
          <path d="M 16 96 A 64 64 0 0 1 144 96"
                fill="none" stroke="rgba(255,255,255,0.06)" stroke-width="10"
                stroke-linecap="round"/>
          <!-- Value arc -->
          <path id="gaugeArc"
                d="M 16 96 A 64 64 0 0 1 144 96"
                fill="none" stroke="url(#gaugeGrad)" stroke-width="10"
                stroke-linecap="round"
                stroke-dasharray="201"
                stroke-dashoffset="201"/>
        </svg>
        <div class="gauge-center">
          <div id="scoreNum">—</div>
          <div id="scoreLevel">—</div>
        </div>
      </div>

      <div class="score-meta">
        <div class="score-desc" id="scoreDesc">Awaiting analysis</div>
        <div class="score-sub" id="scoreSub">Enter a URL above and click Analyse to begin.</div>
        <div class="score-bar-wrap">
          <div class="score-bar" id="scoreBar" style="width:0%"></div>
        </div>
        <div class="score-ticks">
          <span>0 · Safe</span><span>25 · Low</span><span>50 · Med</span>
          <span>75 · High</span><span>100 · Critical</span>
        </div>
      </div>
    </div>
  </div>

  <!-- URL meta -->
  <div class="card" id="metaCard">
    <div class="section-title">URL Intelligence</div>
    <div class="meta-grid" id="metaGrid"></div>
  </div>

  <!-- Security checks -->
  <div class="card" id="checksCard">
    <div class="section-title">Security Checks</div>
    <div class="stats-row" id="statsRow"></div>
    <div class="checks-layout" id="checkGrid"></div>
  </div>

  <!-- Recommendations -->
  <div class="card" id="recCard">
    <div class="section-title">Recommendations</div>
    <ul class="rec-list" id="recList"></ul>
  </div>

</div><!-- /results -->

<footer>
  ShieldScan &mdash; Smart URL Reputation Checker &nbsp;&bull;&nbsp;
  Cybersecurity Project &nbsp;&bull;&nbsp; 2026<br>
  <small>Analysis is heuristic-based. Always exercise caution with unknown URLs.</small>
</footer>

<script>
/* ── constants ──────────────────────────────────────────────────────────── */
const LC = {
  SAFE:     { col:'#34d399', glow:'var(--safe-glow)',  desc:'No threats detected',         sub:'This URL shows no suspicious indicators. Standard safe-browsing practices still apply.' },
  LOW:      { col:'#34d399', glow:'var(--low-glow)',   desc:'Minor indicators present',     sub:'The URL has a few low-priority flags. It is likely safe but worth a second look.' },
  MEDIUM:   { col:'#fbbf24', glow:'var(--med-glow)',   desc:'Caution advised',              sub:'Multiple indicators were found. Do not submit credentials or personal data on this page.' },
  HIGH:     { col:'#fb923c', glow:'var(--high-glow)',  desc:'High risk — avoid if possible', sub:'Strong threat signals detected. Verify through a sandbox (urlscan.io) before visiting.' },
  CRITICAL: { col:'#f87171', glow:'var(--crit-glow)',  desc:'Critical threat detected',     sub:'Do NOT visit this URL. Block and report it to a threat intelligence platform immediately.' },
};
const GAUGE_LEN = 201; // half-circumference of r=64 arc ≈ π×64

/* ── main scan handler ──────────────────────────────────────────────────── */
async function scanURL() {
  const url   = document.getElementById('urlInput').value.trim();
  const errEl = document.getElementById('error-msg');
  errEl.style.display = 'none';

  if (!url) {
    errEl.style.display = 'block';
    errEl.textContent = '⚠ Please enter a URL before scanning.';
    return;
  }

  document.getElementById('scanBtn').disabled = true;
  document.getElementById('spinner').style.display = 'block';
  document.getElementById('results').style.display = 'none';

  try {
    const resp = await fetch('/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });
    const data = await resp.json();
    if (data.error) {
      errEl.style.display = 'block';
      // Show a richer message when the URL is simply unreachable
      if (data.reachable === false) {
        errEl.innerHTML =
          '<strong>🌐 URL Not Reachable</strong><br>' +
          '&#10005;&nbsp;&nbsp;' + data.error + '<br>' +
          '<small style="opacity:.75">Only live, working URLs can be scored. ' +
          'Check the URL for typos and try again.</small>';
      } else {
        errEl.textContent = '✕  ' + data.error;
      }
      return;
    }
    renderResults(data);
  } catch (e) {
    errEl.style.display = 'block';
    errEl.textContent = '✕  Network error: ' + e.message;
  } finally {
    document.getElementById('scanBtn').disabled = false;
    document.getElementById('spinner').style.display = 'none';
  }
}

document.getElementById('urlInput').addEventListener('keydown', e => {
  if (e.key === 'Enter') scanURL();
});

/* ── render ─────────────────────────────────────────────────────────────── */
function renderResults(d) {
  const level = d.risk.level;
  const info  = LC[level] || LC.SAFE;
  const score = d.risk.score;

  /* --- Score gauge --- */
  const offset = GAUGE_LEN - (score / 100) * GAUGE_LEN;
  const arc = document.getElementById('gaugeArc');
  // Reset then animate
  arc.style.transition = 'none';
  arc.style.strokeDashoffset = GAUGE_LEN;
  setTimeout(() => {
    arc.style.transition = 'stroke-dashoffset 1s cubic-bezier(.4,0,.2,1), stroke .6s ease';
    arc.style.strokeDashoffset = offset;
  }, 60);

  const scoreNumEl  = document.getElementById('scoreNum');
  const scoreLevelEl = document.getElementById('scoreLevel');
  scoreNumEl.textContent  = score;
  scoreNumEl.style.color  = info.col;
  scoreLevelEl.textContent = level;
  scoreLevelEl.style.color = info.col;

  document.getElementById('scoreDesc').textContent = info.desc;
  document.getElementById('scoreSub').textContent  = info.sub;
  document.getElementById('scoreCard').style.boxShadow = info.glow;

  /* Progress bar */
  const bar = document.getElementById('scoreBar');
  bar.style.width = '0%';
  setTimeout(() => { bar.style.width = score + '%'; }, 80);

  /* --- Meta grid --- */
  const dnsOk   = d.dns && d.dns.resolved;
  const tlsOk   = d.url && d.url.startsWith('https');
  const httpSt  = d.http_status;
  const httpCls = httpSt && httpSt < 300 ? 'ok' : (httpSt ? 'bad' : '');
  const metaItems = [
    { label: 'Domain',      val: d.domain || '—',        cls: '' },
    { label: 'TLD',         val: d.tld ? '.' + d.tld : '—', cls: '' },
    { label: 'Resolved IP', val: d.ip_address || 'Unresolved', cls: dnsOk ? 'ok' : 'bad' },
    { label: 'HTTP Status', val: httpSt ? 'HTTP ' + httpSt : '—', cls: httpCls },
    { label: 'Protocol',    val: tlsOk ? 'HTTPS ✓' : 'HTTP ✗',  cls: tlsOk ? 'ok' : 'bad' },
    { label: 'Entropy',     val: d.entropy.entropy + ' bits', cls: d.entropy.flagged ? 'bad' : 'ok' },
    { label: 'DGA Flag',    val: d.entropy.flagged ? 'Yes — suspicious' : 'No', cls: d.entropy.flagged ? 'bad' : 'ok' },
    { label: 'Redirects',   val: d.redirects.hops + ' hop(s)', cls: d.redirects.flagged ? 'bad' : 'ok' },
    { label: 'Scanned',     val: d.scanned_at.replace('T',' ').replace('Z','') + ' UTC', cls: '' },
  ];
  document.getElementById('metaGrid').innerHTML = metaItems.map(m =>
    `<div class="meta-item">
       <div class="meta-label">${m.label}</div>
       <div class="meta-val ${m.cls}">${m.val}</div>
     </div>`
  ).join('');

  /* --- Stats pills --- */
  const passed = d.pattern_checks.filter(c => !c.flag).length;
  const failed = d.pattern_checks.filter(c =>  c.flag).length;
  document.getElementById('statsRow').innerHTML =
    `<span class="stat-pill pass-pill"><span class="stat-dot"></span>${passed} Passed</span>
     <span class="stat-pill fail-pill"><span class="stat-dot"></span>${failed} Flagged</span>`;

  /* --- Checks grid --- */
  document.getElementById('checkGrid').innerHTML = d.pattern_checks.map(c =>
    `<div class="check-item ${c.flag ? 'fail' : 'pass'}">
       <div class="check-icon-box">${c.flag ? '✕' : '✓'}</div>
       <div class="check-text">
         <div class="check-name">${c.name}</div>
         <div class="check-detail">${c.detail}</div>
       </div>
     </div>`
  ).join('');

  /* --- Recommendations --- */
  document.getElementById('recList').innerHTML = d.recommendations.map((r, i) =>
    `<li><div class="rec-num">${i + 1}</div><span>${r}</span></li>`
  ).join('');

  /* --- Show results --- */
  document.getElementById('results').style.display = 'block';
  setTimeout(() =>
    document.getElementById('results').scrollIntoView({ behavior: 'smooth', block: 'start' }),
    120
  );
}

/* ═══════════════════════════════════════════════════════════════════════════
   CYBERSECURITY BACKGROUND — HD Canvas Engine
   Layers (back → front):
     1. Deep space base gradient
     2. Perspective hex-tile grid with shimmer
     3. Animated network node graph (nodes + edges)
     4. Floating glyphs  (0/1 binary · hex chars · shield/lock symbols)
     5. Horizontal scanline sweep
     6. Vignette overlay
   ═══════════════════════════════════════════════════════════════════════════ */
(function () {
  const cvs = document.getElementById('bg-canvas');
  const ctx  = cvs.getContext('2d');
  const DPR  = window.devicePixelRatio || 1;

  // ── resize ───────────────────────────────────────────────────────────────
  let W, H;
  function resize() {
    W = window.innerWidth;
    H = window.innerHeight;
    cvs.width  = Math.round(W * DPR);
    cvs.height = Math.round(H * DPR);
    cvs.style.width  = W + 'px';
    cvs.style.height = H + 'px';
    ctx.setTransform(DPR, 0, 0, DPR, 0, 0);
  }
  window.addEventListener('resize', () => { resize(); initScene(); });
  resize();

  // ── palette ──────────────────────────────────────────────────────────────
  const C = {
    bg:      '#05070f',
    cyan:    'rgba(99,179,237,',
    violet:  'rgba(167,139,250,',
    green:   'rgba(52,211,153,',
    red:     'rgba(248,113,113,',
  };

  // ── hex grid ─────────────────────────────────────────────────────────────
  const HEX_R   = 36;          // outer radius
  const HEX_H   = HEX_R * Math.sqrt(3);
  let hexShimmer = [];

  function hexPts(cx, cy, r) {
    const pts = [];
    for (let i = 0; i < 6; i++) {
      const a = (Math.PI / 3) * i - Math.PI / 6;
      pts.push([cx + r * Math.cos(a), cy + r * Math.sin(a)]);
    }
    return pts;
  }

  function buildHexGrid() {
    hexShimmer = [];
    const cols = Math.ceil(W / (HEX_R * 3)) + 2;
    const rows = Math.ceil(H / HEX_H) + 2;
    for (let row = -1; row < rows; row++) {
      for (let col = -1; col < cols; col++) {
        const cx = col * HEX_R * 3 + (row % 2 === 0 ? 0 : HEX_R * 1.5);
        const cy = row * HEX_H * 0.5;
        hexShimmer.push({
          cx, cy,
          phase: Math.random() * Math.PI * 2,
          speed: 0.002 + Math.random() * 0.004,
          amp:   0.3   + Math.random() * 0.5,
          col:   Math.random() > 0.15 ? C.cyan : (Math.random() > 0.5 ? C.violet : C.green),
        });
      }
    }
  }

  function drawHexGrid(t) {
    for (const h of hexShimmer) {
      const alpha = 0.018 + Math.sin(h.phase + t * h.speed) * 0.012 * h.amp;
      if (alpha <= 0) continue;
      const pts = hexPts(h.cx, h.cy, HEX_R - 1);
      ctx.beginPath();
      ctx.moveTo(pts[0][0], pts[0][1]);
      for (let i = 1; i < 6; i++) ctx.lineTo(pts[i][0], pts[i][1]);
      ctx.closePath();
      ctx.strokeStyle = h.col + Math.min(alpha, 0.08) + ')';
      ctx.lineWidth = 0.6;
      ctx.stroke();
    }
  }

  // ── network nodes ─────────────────────────────────────────────────────────
  const NODE_COUNT = 42;
  const EDGE_DIST  = 190;
  let nodes = [];

  const NODE_ICONS = ['⬡', '◈', '◉', '▣'];   // rendered as unicode fills

  function initNodes() {
    nodes = [];
    for (let i = 0; i < NODE_COUNT; i++) {
      const tier = Math.random();
      nodes.push({
        x:   Math.random() * W,
        y:   Math.random() * H,
        vx:  (Math.random() - 0.5) * 0.22,
        vy:  (Math.random() - 0.5) * 0.22,
        r:   tier > 0.85 ? 5 : tier > 0.6 ? 3.5 : 2,
        // visual type
        type: tier > 0.85 ? 'hub' : tier > 0.6 ? 'relay' : 'leaf',
        // pulse
        pPhase: Math.random() * Math.PI * 2,
        pSpeed: 0.018 + Math.random() * 0.025,
        // colour
        col:  Math.random() > 0.3 ? C.cyan : (Math.random() > 0.5 ? C.violet : C.green),
        // data packet travelling along an edge
        packet: null,
      });
    }
  }

  function drawNodes(t) {
    // edges first
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i + 1; j < nodes.length; j++) {
        const a = nodes[i], b = nodes[j];
        const dx = a.x - b.x, dy = a.y - b.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        if (dist > EDGE_DIST) continue;
        const alpha = (1 - dist / EDGE_DIST) * 0.13;
        const grad = ctx.createLinearGradient(a.x, a.y, b.x, b.y);
        grad.addColorStop(0, a.col + alpha + ')');
        grad.addColorStop(1, b.col + alpha + ')');
        ctx.beginPath();
        ctx.moveTo(a.x, a.y);
        ctx.lineTo(b.x, b.y);
        ctx.strokeStyle = grad;
        ctx.lineWidth = 0.8;
        ctx.stroke();
      }
    }

    // data packets — tiny glowing dots travelling edges
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.packet) {
        const tgt = nodes[n.packet.target];
        n.packet.prog += n.packet.speed;
        if (n.packet.prog >= 1) { n.packet = null; continue; }
        const px = n.x + (tgt.x - n.x) * n.packet.prog;
        const py = n.y + (tgt.y - n.y) * n.packet.prog;
        const pg = ctx.createRadialGradient(px, py, 0, px, py, 5);
        pg.addColorStop(0, n.col + '0.9)');
        pg.addColorStop(1, n.col + '0)');
        ctx.beginPath();
        ctx.arc(px, py, 5, 0, Math.PI * 2);
        ctx.fillStyle = pg;
        ctx.fill();
      } else if (Math.random() < 0.0015) {
        // spawn new packet toward a nearby node
        const candidates = nodes
          .map((b, j) => ({ j, d: Math.hypot(n.x - b.x, n.y - b.y) }))
          .filter(e => e.j !== i && e.d < EDGE_DIST);
        if (candidates.length) {
          const tgt = candidates[Math.floor(Math.random() * candidates.length)];
          n.packet = { target: tgt.j, prog: 0, speed: 0.005 + Math.random() * 0.01 };
        }
      }
    }

    // nodes
    for (const n of nodes) {
      const pulse = 0.55 + 0.45 * Math.sin(n.pPhase + t * n.pSpeed);

      // outer halo for hub nodes
      if (n.type === 'hub') {
        const halo = ctx.createRadialGradient(n.x, n.y, n.r, n.x, n.y, n.r * 6);
        halo.addColorStop(0, n.col + (0.25 * pulse) + ')');
        halo.addColorStop(1, n.col + '0)');
        ctx.beginPath();
        ctx.arc(n.x, n.y, n.r * 6, 0, Math.PI * 2);
        ctx.fillStyle = halo;
        ctx.fill();
      }

      // node dot
      const g = ctx.createRadialGradient(n.x, n.y, 0, n.x, n.y, n.r * 2.5);
      g.addColorStop(0, n.col + (0.9 * pulse) + ')');
      g.addColorStop(0.5, n.col + (0.4 * pulse) + ')');
      g.addColorStop(1, n.col + '0)');
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r * 2.5, 0, Math.PI * 2);
      ctx.fillStyle = g;
      ctx.fill();

      // crisp centre dot
      ctx.beginPath();
      ctx.arc(n.x, n.y, n.r * 0.7, 0, Math.PI * 2);
      ctx.fillStyle = n.col + '1)';
      ctx.fill();

      // move
      n.x += n.vx; n.y += n.vy;
      if (n.x < -40)  n.x = W + 40;
      if (n.x > W+40) n.x = -40;
      if (n.y < -40)  n.y = H + 40;
      if (n.y > H+40) n.y = -40;
    }
  }

  // ── floating glyphs ───────────────────────────────────────────────────────
  const GLYPH_CHARS = [
    '0','1','A','F','E','7','3','C','B','D','9',
    '01','FF','C4','3A','7E','B2',
    '🛡','⚿','⊞','⌁','⊛','✦',
  ];
  let glyphs = [];

  function initGlyphs() {
    glyphs = [];
    const count = Math.max(18, Math.floor((W * H) / 52000));
    for (let i = 0; i < count; i++) {
      glyphs.push(spawnGlyph(true));
    }
  }

  function spawnGlyph(randomY) {
    const size = 9 + Math.random() * 10;
    return {
      x:     Math.random() * W,
      y:     randomY ? Math.random() * H : H + 20,
      vy:    -(0.12 + Math.random() * 0.25),
      alpha: 0.04 + Math.random() * 0.09,
      size,
      char:  GLYPH_CHARS[Math.floor(Math.random() * GLYPH_CHARS.length)],
      col:   Math.random() > 0.4 ? C.cyan : (Math.random() > 0.5 ? C.violet : C.green),
      fadeIn: 0, fadeMax: 80 + Math.random() * 120,
    };
  }

  function drawGlyphs() {
    ctx.save();
    for (let i = 0; i < glyphs.length; i++) {
      const g = glyphs[i];
      g.y  += g.vy;
      g.fadeIn++;
      const fade = Math.min(g.fadeIn / g.fadeMax, 1);
      const endFade = g.y < -30 ? Math.max(0, 1 + g.y / 60) : 1;
      ctx.globalAlpha = g.alpha * fade * endFade;
      ctx.fillStyle   = g.col + '1)';
      ctx.font        = `${g.size}px 'JetBrains Mono', monospace`;
      ctx.fillText(g.char, g.x, g.y);
      if (g.y < -40) glyphs[i] = spawnGlyph(false);
    }
    ctx.restore();
  }

  // ── scanline sweep ────────────────────────────────────────────────────────
  let scanY = -80;
  const SCAN_SPEED = 0.55;

  function drawScanline() {
    scanY += SCAN_SPEED;
    if (scanY > H + 80) scanY = -80;

    const sg = ctx.createLinearGradient(0, scanY - 60, 0, scanY + 60);
    sg.addColorStop(0,   'rgba(99,179,237,0)');
    sg.addColorStop(0.45,'rgba(99,179,237,0.04)');
    sg.addColorStop(0.5, 'rgba(99,179,237,0.12)');
    sg.addColorStop(0.55,'rgba(99,179,237,0.04)');
    sg.addColorStop(1,   'rgba(99,179,237,0)');
    ctx.fillStyle = sg;
    ctx.fillRect(0, scanY - 60, W, 120);

    // crisp scan line
    ctx.beginPath();
    ctx.moveTo(0, scanY);
    ctx.lineTo(W, scanY);
    ctx.strokeStyle = 'rgba(99,179,237,0.18)';
    ctx.lineWidth = 1;
    ctx.stroke();
  }

  // ── radial vignette ───────────────────────────────────────────────────────
  function drawVignette() {
    const vg = ctx.createRadialGradient(W/2, H/2, H*0.3, W/2, H/2, H*0.9);
    vg.addColorStop(0, 'rgba(5,7,15,0)');
    vg.addColorStop(1, 'rgba(5,7,15,0.72)');
    ctx.fillStyle = vg;
    ctx.fillRect(0, 0, W, H);
  }

  // ── ambient glow orbs ─────────────────────────────────────────────────────
  const orbs = [
    { x: 0.18, y: 0.08, rx: 0.38, ry: 0.28, col: 'rgba(99,179,237,',  a: 0.055 },
    { x: 0.82, y: 0.06, rx: 0.32, ry: 0.24, col: 'rgba(167,139,250,', a: 0.045 },
    { x: 0.50, y: 0.85, rx: 0.45, ry: 0.20, col: 'rgba(52,211,153,',  a: 0.028 },
  ];

  function drawOrbs() {
    for (const o of orbs) {
      const cx = o.x * W, cy = o.y * H;
      const rx = o.rx * W, ry = o.ry * H;
      ctx.save();
      ctx.scale(1, ry / rx);
      const g = ctx.createRadialGradient(cx, cy * (rx/ry), 0, cx, cy * (rx/ry), rx);
      g.addColorStop(0, o.col + o.a + ')');
      g.addColorStop(1, o.col + '0)');
      ctx.fillStyle = g;
      ctx.beginPath();
      ctx.arc(cx, cy * (rx/ry), rx, 0, Math.PI * 2);
      ctx.fill();
      ctx.restore();
    }
  }

  // ── scene init ────────────────────────────────────────────────────────────
  function initScene() {
    buildHexGrid();
    initNodes();
    initGlyphs();
  }
  initScene();

  // ── main loop ─────────────────────────────────────────────────────────────
  let t = 0;
  function frame() {
    t++;
    // base fill
    ctx.fillStyle = C.bg;
    ctx.fillRect(0, 0, W, H);

    drawOrbs();
    drawHexGrid(t);
    drawNodes(t);
    drawGlyphs();
    drawScanline();
    drawVignette();

    requestAnimationFrame(frame);
  }
  frame();
})();
</script>
</body>
</html>
"""
print('HTML template loaded (' + str(len(HTML_TEMPLATE)) + ' chars).')

# ## Cell 10 — Quick Demo Scan (No Web Server Required)


import json

# Quick demo scan (no web server needed)
demo_urls = [
    'http://paypal-secure-login.tk/verify?id=abc',
    'https://www.google.com',
    'http://192.168.1.1/login',
]

for url in demo_urls:
    result = scanner.scan(url)
    print('=' * 58)
    print(f"URL    : {result['url']}")
    # Reachability gate: scanner may return an error for offline/fake URLs
    if not result.get('reachable', True):
        print(f"STATUS : NOT REACHABLE — {result.get('error', 'unknown error')}")
        print("SCORE  : N/A  (only live URLs are scored)")
    else:
        risk    = result['risk']
        flagged = [c['name'] for c in result['pattern_checks'] if c['flag']]
        print(f"STATUS : Reachable (HTTP {result.get('http_status', '?')})")
        print(f"Score  : {risk['score']} / 100   Level : {risk['level']}")
        print(f"Domain : {result['domain']}   IP: {result['ip_address']}")
        print(f"Entropy: {result['entropy']['entropy']} bits   DGA: {result['entropy']['flagged']}")
        print(f"TLD    : {result['tld_analysis']['detail']}")
        print(f"Flagged: {', '.join(flagged) if flagged else 'None'}")
print('=' * 58)

# ## Cell 11 — Start Flask Web Server
# 
# > ⚠️ This cell **blocks** until you stop it.  
# > Open **http://127.0.0.1:5001** in your browser.  
# > Use **Kernel → Interrupt Kernel** to stop.


app = Flask(__name__)

# ── Routes ──────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the main web interface."""
    return render_template_string(HTML_TEMPLATE)


@app.route("/scan", methods=["POST"])
def scan():
    """API endpoint: accepts {url} JSON, returns full analysis report."""
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()

    if not url:
        return jsonify({"error": "URL is required"}), 400
    if len(url) > 2048:
        return jsonify({"error": "URL is too long (max 2048 characters)"}), 400

    try:
        result = scanner.scan(url)
        return jsonify(result)
    except Exception as exc:
        return jsonify({"error": f"Scan failed: {str(exc)}"}), 500


@app.route("/health")
def health():
    """Simple health-check endpoint."""
    return jsonify({"status": "ok", "service": "SmartURLReputationChecker"})

import os
port = int(os.environ.get('PORT', 5001))
print('=' * 60)
print('  Smart URL Reputation Checker — starting server')
print(f'  Open http://127.0.0.1:{port} in your browser')
print('  Use Kernel > Interrupt Kernel to stop')
print('=' * 60)
app.run(debug=False, use_reloader=False, host='0.0.0.0', port=port, threaded=True)