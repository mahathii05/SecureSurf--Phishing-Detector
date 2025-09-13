# phishing_tool.py
"""
Lightweight heuristic phishing checker for Watsonx Orchestrate (Option A).
No scikit-learn dependency — safe to import in WXO tool runtime.

Usage:
  - Import into Orchestrate:
      orchestrate tools import -k python -f phishing_tool.py
  - Test locally:
      python phishing_tool.py
"""

import re
from urllib.parse import urlparse
from ibm_watsonx_orchestrate.agent_builder.tools import tool

# Shorteners and suspicious keyword patterns (tune as needed)
SHORTENERS = re.compile(
    r"(bit\.ly|tinyurl|goo\.gl|ow\.ly|t\.co|cutt\.ly|is\.gd|tiny\.cc|short\.ly)",
    re.I,
)
SUSPICIOUS_WORDS = [
    "login", "signin", "secure", "account", "update", "verify",
    "bank", "confirm", "password", "webscr", "admin", "paypal", "ebay", "meta", "wallet", "claim"
]

def _has_ip(netloc: str) -> bool:
    return bool(re.match(r'^\d{1,3}(\.\d{1,3}){3}$', netloc))

def _count_digits(s: str) -> int:
    return sum(ch.isdigit() for ch in s)

@tool
def check_url(url: str) -> str:
    """
    Classify a raw URL string as 'Phishing' or 'Legitimate' using simple heuristics.
    Returns a string containing classification, score, confidence (approx) and reasons.
    """
    try:
        if not isinstance(url, str) or url.strip() == "":
            return "Please provide a non-empty URL string."

        u = url.strip()
        # ensure scheme for urlparse
        if not re.match(r'^[a-zA-Z]+://', u):
            u = "http://" + u

        parsed = urlparse(u)
        netloc = parsed.netloc.lower()
        path = parsed.path.lower()
        full = (netloc + path + ("?" + parsed.query if parsed.query else "")).lower()

        score = 0
        reasons = []

        # rule 1: IP address in host -> strong signal
        if _has_ip(netloc):
            score += 4
            reasons.append("IP address in domain")

        # rule 2: URL shortener services -> strong signal
        if SHORTENERS.search(u):
            score += 3
            reasons.append("Shortening service")

        # rule 3: '@' symbol -> strong signal
        if "@" in u:
            score += 3
            reasons.append("'@' symbol in URL")

        # rule 4: long URL -> weak signal
        if len(u) > 75:
            score += 1
            reasons.append("Long URL")

        # rule 5: suspicious keywords in domain/path
        kw_hits = [w for w in SUSPICIOUS_WORDS if w in full]
        if kw_hits:
            score += 2
            reasons.append("Suspicious keywords: " + ", ".join(sorted(set(kw_hits))))

        # rule 6: many digits in host -> weak signal
        digit_count = _count_digits(netloc)
        if digit_count > 4:
            score += 1
            reasons.append(f"{digit_count} digits in domain")

        # rule 7: many subdomains -> weak signal
        if netloc.count(".") > 2:
            score += 1
            reasons.append("Many subdomains")

        # rule 8: hyphen in domain -> weak signal
        if "-" in netloc:
            score += 1
            reasons.append("Hyphen in domain")

        # final decision threshold (tuneable)
        label = "Phishing" if score >= 4 else "Legitimate"

        # simple confidence proxy (0.2 baseline + 0.18 per score point)
        conf = min(0.99, 0.20 + 0.18 * score)
        reasons_text = ", ".join(reasons) if reasons else "none detected"

        return (
            f"URL: {url}\n"
            f"Classification: {label}\n"
            f"Score: {score}\n"
            f"Confidence (approx): {conf:.2f}\n"
            f"Reasons: {reasons_text}"
        )

    except Exception as e:
        return f"[ERROR] Exception during check: {str(e)}"


# Local test harness so you can run it directly
if __name__ == "__main__":
    tests = [
        "http://metamsk01lgix.godaddysites.com/",
        "http://bit.ly/2abcde",
        "https://www.wikipedia.org",
        "http://192.168.1.1/login",
        "https://secure-paypal.com/verify"
    ]
    for t in tests:
        print("===\nInput:", t)
        print(check_url(t))
        print()
