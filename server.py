"""URL AI MCP Server — URL parsing and analysis tools."""

import sys, os
sys.path.insert(0, os.path.expanduser('~/clawd/meok-labs-engine/shared'))
from auth_middleware import check_access

import hashlib
import re
import time
from urllib.parse import urlparse, parse_qs, urlencode, quote, unquote
from typing import Any
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("url-ai-mcp")
_calls: dict[str, list[float]] = {}
DAILY_LIMIT = 50

def _rate_check(tool: str) -> bool:
    now = time.time()
    _calls.setdefault(tool, [])
    _calls[tool] = [t for t in _calls[tool] if t > now - 86400]
    if len(_calls[tool]) >= DAILY_LIMIT:
        return False
    _calls[tool].append(now)
    return True

@mcp.tool()
def parse_url(url: str, api_key: str = "") -> dict[str, Any]:
    """Parse a URL into its components with detailed analysis."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("parse_url"):
        return {"error": "Rate limit exceeded (50/day)"}
    try:
        p = urlparse(url)
    except Exception as e:
        return {"error": f"Invalid URL: {e}"}
    params = parse_qs(p.query)
    path_parts = [s for s in p.path.split("/") if s]
    ext = ""
    if path_parts and "." in path_parts[-1]:
        ext = path_parts[-1].rsplit(".", 1)[-1]
    return {
        "scheme": p.scheme, "hostname": p.hostname, "port": p.port,
        "path": p.path, "path_segments": path_parts, "query_params": params,
        "fragment": p.fragment, "username": p.username, "password": "***" if p.password else None,
        "file_extension": ext, "is_secure": p.scheme == "https",
        "netloc": p.netloc, "full_url": url
    }

@mcp.tool()
def shorten_url_data(url: str, api_key: str = "") -> dict[str, Any]:
    """Generate a deterministic short URL hash (does not create actual redirect)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("shorten_url_data"):
        return {"error": "Rate limit exceeded (50/day)"}
    h = hashlib.sha256(url.encode()).hexdigest()[:8]
    encoded = quote(url, safe="")
    return {
        "original_url": url, "short_hash": h,
        "suggested_short": f"https://s.url/{h}",
        "url_encoded": encoded, "url_decoded": unquote(encoded),
        "original_length": len(url), "note": "Hash-based short URL data. Implement redirect service separately."
    }

@mcp.tool()
def check_url_safety(url: str, api_key: str = "") -> dict[str, Any]:
    """Analyze URL for potential safety issues (heuristic-based, no external calls)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("check_url_safety"):
        return {"error": "Rate limit exceeded (50/day)"}
    warnings = []
    score = 100
    p = urlparse(url)
    if p.scheme != "https":
        warnings.append("Not using HTTPS")
        score -= 20
    if p.hostname and re.search(r'\d+\.\d+\.\d+\.\d+', p.hostname):
        warnings.append("IP address instead of domain name")
        score -= 25
    if p.hostname and len(p.hostname) > 50:
        warnings.append("Unusually long hostname")
        score -= 15
    suspicious_tlds = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz"]
    if p.hostname and any(p.hostname.endswith(t) for t in suspicious_tlds):
        warnings.append(f"Suspicious TLD")
        score -= 20
    if p.port and p.port not in (80, 443, 8080, 8443):
        warnings.append(f"Non-standard port: {p.port}")
        score -= 10
    phishing_kw = ["login", "signin", "account", "secure", "update", "verify", "banking"]
    if p.hostname and any(k in p.hostname.lower() for k in phishing_kw):
        warnings.append("Contains phishing-related keywords in hostname")
        score -= 20
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        warnings.append("Contains @ in authority (potential redirect trick)")
        score -= 30
    if p.hostname and p.hostname.count(".") > 4:
        warnings.append("Excessive subdomains")
        score -= 10
    score = max(0, score)
    rating = "Safe" if score >= 80 else "Caution" if score >= 50 else "Suspicious" if score >= 30 else "Dangerous"
    return {"url": url, "safety_score": score, "rating": rating, "warnings": warnings}

@mcp.tool()
def extract_metadata(url: str, api_key: str = "") -> dict[str, Any]:
    """Extract metadata from URL structure (no HTTP requests)."""
    allowed, msg, tier = check_access(api_key)
    if not allowed:
        return {"error": msg, "upgrade_url": "https://meok.ai/pricing"}

    if not _rate_check("extract_metadata"):
        return {"error": "Rate limit exceeded (50/day)"}
    p = urlparse(url)
    params = parse_qs(p.query)
    path_parts = [s for s in p.path.split("/") if s]
    # Detect common URL patterns
    patterns = []
    if re.search(r'/\d{4}/\d{2}/\d{2}/', p.path):
        patterns.append("date-based (blog/news)")
    if re.search(r'/api/v\d+/', p.path):
        patterns.append("API endpoint")
    if re.search(r'/[a-f0-9]{24,}', p.path):
        patterns.append("contains hash/ID")
    if "utm_" in p.query:
        patterns.append("has UTM tracking parameters")
    utm = {k: v[0] for k, v in params.items() if k.startswith("utm_")}
    domain_parts = p.hostname.split(".") if p.hostname else []
    tld = domain_parts[-1] if domain_parts else ""
    sld = domain_parts[-2] if len(domain_parts) >= 2 else ""
    return {
        "domain": p.hostname, "tld": tld, "second_level_domain": sld,
        "path_depth": len(path_parts), "param_count": len(params),
        "detected_patterns": patterns, "utm_params": utm,
        "has_fragment": bool(p.fragment), "estimated_type": "page" if not path_parts or "." not in path_parts[-1] else path_parts[-1].rsplit(".")[-1]
    }

if __name__ == "__main__":
    mcp.run()
