"""
PhishLens — URL Target Guard (SSRF Protection)

Resolves the hostname from a URL and blocks private, loopback, link-local,
and cloud-metadata IP addresses.  This prevents server-side request forgery
(SSRF) where an attacker tricks the scanner into probing internal services.

The guard resolves the hostname ONCE and returns the resolved IP so callers
can connect to the resolved address directly, preventing DNS rebinding.

Set ALLOW_PRIVATE_TARGETS=true in .env for local development ONLY.
This must NEVER be set in production (Render, etc.).
"""

import ipaddress
import os
import socket
from urllib.parse import urlparse

from loguru import logger


# Cloud metadata endpoints (AWS, GCP, Azure) — block even without reverse DNS
_CLOUD_METADATA_IPS = frozenset({
    "169.254.169.254",   # AWS / GCP / most clouds
    "metadata.google.internal",
    "100.100.100.200",   # Alibaba Cloud
})

_ALLOW_PRIVATE = os.environ.get("ALLOW_PRIVATE_TARGETS", "").lower() in ("true", "1", "yes")


class PrivateTargetError(Exception):
    """Raised when a URL resolves to a blocked (private/internal) address."""
    pass


def is_blocked_ip(ip_str: str) -> bool:
    """
    Return True if the IP address is not globally routable (not addr.is_global)
    or is a known cloud metadata address.
    """
    if ip_str in _CLOUD_METADATA_IPS:
        return True

    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return False  # not a valid IP string — caller will resolve

    return not addr.is_global


_is_blocked_ip = is_blocked_ip


def resolve_and_guard(url: str) -> tuple[str, str]:
    """
    Resolve the hostname from *url* and enforce the SSRF blocklist.

    Returns
    -------
    (hostname, resolved_ip) on success.

    Raises
    ------
    PrivateTargetError
        If the resolved IP is private/internal and ALLOW_PRIVATE_TARGETS
        is not set.
    socket.gaierror / ValueError
        If hostname cannot be resolved or URL is malformed.
    """
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError(f"Cannot extract hostname from URL: {url}")

    # If the hostname directly is an IP or in cloud metadata
    if is_blocked_ip(hostname) and not _ALLOW_PRIVATE:
        logger.warning(
            "[URL Guard] Blocked private/internal target hostname: {}", hostname
        )
        raise PrivateTargetError(
            f"Target {hostname} is a blocked address"
        )

    # Resolve to IP
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception:
        pass

    if not resolved_ip:
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
            if addr_infos:
                resolved_ip = addr_infos[0][4][0]
        except Exception:
            pass

    if not resolved_ip:
        try:
            ipaddress.ip_address(hostname)
            resolved_ip = hostname
        except ValueError:
            raise socket.gaierror(f"Could not resolve hostname: {hostname}")

    if is_blocked_ip(resolved_ip) and not _ALLOW_PRIVATE:
        logger.warning(
            "[URL Guard] Blocked private/internal target: {} → {}",
            hostname, resolved_ip,
        )
        raise PrivateTargetError(
            f"Target {hostname} resolves to blocked address {resolved_ip}"
        )

    logger.debug("[URL Guard] Resolved {} → {} (allowed)", hostname, resolved_ip)
    return hostname, resolved_ip


def check_url_after_redirect(final_url: str) -> None:
    """
    Re-check the final URL after redirects to prevent DNS rebinding.

    Raises PrivateTargetError if the final URL resolves to a blocked IP.
    """
    parsed = urlparse(final_url)
    hostname = parsed.hostname
    if not hostname:
        return  # can't check, let it pass

    if is_blocked_ip(hostname) and not _ALLOW_PRIVATE:
        logger.warning(
            "[URL Guard] Blocked post-redirect target hostname: {}", hostname
        )
        raise PrivateTargetError(
            f"Redirect target {hostname} is a blocked address"
        )

    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except Exception:
        pass

    if not resolved_ip:
        try:
            addr_infos = socket.getaddrinfo(hostname, None)
            if addr_infos:
                resolved_ip = addr_infos[0][4][0]
        except Exception:
            pass

    if not resolved_ip:
        try:
            ipaddress.ip_address(hostname)
            resolved_ip = hostname
        except ValueError:
            return  # DNS failure after redirect — behavior engine will handle

    if is_blocked_ip(resolved_ip) and not _ALLOW_PRIVATE:
        logger.warning(
            "[URL Guard] Blocked post-redirect target: {} → {}",
            hostname, resolved_ip,
        )
        raise PrivateTargetError(
            f"Redirect target {hostname} resolves to blocked address {resolved_ip}"
        )
