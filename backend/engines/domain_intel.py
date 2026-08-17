"""
PhishLens — Domain Intelligence Engine

Gathers domain-level intelligence: WHOIS age, registrar, SSL certificate
validity, and DNSSEC status. Every external lookup is individually
wrapped in try/except with a 5-second timeout so a single failure
never crashes the whole function.

No imports from database.py, models.py, or schemas.py.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse

import whois
import dns.resolver
import dns.name


# ---------------------------------------------------------------------------
# Internal helpers — each one handles its own errors
# ---------------------------------------------------------------------------

def _extract_domain(url: str) -> str:
    """Pull the bare hostname out of a URL string."""
    parsed = urlparse(url)
    domain = parsed.hostname or parsed.path.split("/")[0]
    # Strip a leading "www." so WHOIS and DNS lookups work on the root domain
    if domain and domain.startswith("www."):
        domain = domain[4:]
    return domain


def _whois_lookup(domain: str) -> dict:
    """
    Query WHOIS for creation_date and registrar.
    Returns {"domain_age_days": int|None, "registrar": str|None}.
    """
    result = {"domain_age_days": None, "registrar": None}
    try:
        w = whois.whois(domain)

        # --- registrar ---
        if w.registrar:
            result["registrar"] = str(w.registrar)

        # --- creation_date → age in days ---
        creation = w.creation_date
        if creation:
            # Some registrars return a list of dates; take the earliest
            if isinstance(creation, list):
                creation = min(creation)
            # Ensure timezone-aware comparison
            now = datetime.now(timezone.utc)
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            age_delta = now - creation
            result["domain_age_days"] = max(age_delta.days, 0)
    except Exception:
        pass  # WHOIS can fail for many reasons; leave fields as None

    return result


def _ssl_check(domain: str, timeout: int = 5) -> dict:
    """
    Attempt an SSL handshake on port 443 and inspect the certificate.
    Returns {"ssl_valid": bool, "ssl_issuer": str|None}.
    """
    result = {"ssl_valid": False, "ssl_issuer": None}
    try:
        import certifi
        ctx = ssl.create_default_context(cafile=certifi.where())
        with socket.create_connection((domain, 443), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    result["ssl_valid"] = True
                    # Extract the issuer's Organization name
                    issuer_fields = dict(
                        item
                        for sub in cert.get("issuer", ())
                        for item in sub
                    )
                    result["ssl_issuer"] = issuer_fields.get("organizationName")
    except Exception:
        pass  # Connection refused, timeout, cert error → ssl_valid stays False

    return result


def _dnssec_check(domain: str, timeout: int = 5) -> bool:
    """
    Check whether a DS record exists for the domain, indicating DNSSEC.
    Returns True if a DS record is found, False otherwise.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = timeout
        resolver.resolve(domain, "DS")
        return True
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers, dns.resolver.Timeout,
            dns.name.EmptyLabel, Exception):
        return False


# ---------------------------------------------------------------------------
# Risk scoring
# ---------------------------------------------------------------------------

def _compute_domain_score(
    domain_age_days: int | None,
    ssl_valid: bool,
    dnssec_enabled: bool,
) -> float:
    """
    Combine domain intelligence signals into a 0-100 risk score.

    Higher = more suspicious.
    - Very young domain (< 30 days):  up to +40
    - No SSL:                         +30
    - No DNSSEC:                      +10
    - Unknown age (WHOIS failed):     +15 (mild penalty for lack of data)
    """
    score = 0.0

    # Domain age contribution
    if domain_age_days is None:
        score += 15  # can't verify age → small penalty
    elif domain_age_days < 30:
        score += 40  # brand-new domain
    elif domain_age_days < 90:
        score += 25
    elif domain_age_days < 365:
        score += 10
    # > 1 year → no penalty

    # SSL contribution
    if not ssl_valid:
        score += 30

    # DNSSEC contribution
    if not dnssec_enabled:
        score += 10

    return round(min(score, 100.0), 1)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_domain(url: str) -> dict:
    """
    Analyze the domain extracted from *url* and return intelligence fields.

    Parameters
    ----------
    url : str
        The full URL to analyze (e.g. "https://example.com/path").

    Returns
    -------
    dict with keys:
        domain_age_days, registrar, ssl_valid, ssl_issuer,
        dnssec_enabled, domain_score
    """
    domain = _extract_domain(url)

    # Each lookup is independent; failures are silenced individually
    whois_data = _whois_lookup(domain)
    ssl_data = _ssl_check(domain)
    dnssec_enabled = _dnssec_check(domain)

    domain_score = _compute_domain_score(
        domain_age_days=whois_data["domain_age_days"],
        ssl_valid=ssl_data["ssl_valid"],
        dnssec_enabled=dnssec_enabled,
    )

    return {
        "domain_age_days": whois_data["domain_age_days"],
        "registrar": whois_data["registrar"],
        "ssl_valid": ssl_data["ssl_valid"],
        "ssl_issuer": ssl_data["ssl_issuer"],
        "dnssec_enabled": dnssec_enabled,
        "domain_score": domain_score,
    }
