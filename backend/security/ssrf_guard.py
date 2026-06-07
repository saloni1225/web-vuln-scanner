"""
AdaptiveScan SSRF Prevention
=============================
Blocks scan targets that resolve to private / loopback / link-local addresses.
Protects the scanner from being weaponized to probe internal infrastructure.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

from fastapi import HTTPException, status


# RFC1918 + loopback + link-local + multicast ranges that are never valid scan targets
_BLOCKED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("10.0.0.0/8"),         # RFC1918 class A
    ipaddress.ip_network("172.16.0.0/12"),      # RFC1918 class B
    ipaddress.ip_network("192.168.0.0/16"),     # RFC1918 class C
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("::1/128"),            # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),           # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),          # IPv6 link-local
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
]

# Blocked hostnames that should never be used as targets
_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "broadcasthost",
}

# Only these schemes are allowed in scan targets
_ALLOWED_SCHEMES = {"http", "https"}


def _is_private(ip_str: str) -> bool:
    """Return True if the IP address falls in a blocked network range."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in _BLOCKED_NETWORKS)
    except ValueError:
        return True  # Unparseable → block it


def _resolve_hostname(hostname: str) -> list[str]:
    """Resolve a hostname to a list of IP addresses."""
    try:
        results = socket.getaddrinfo(hostname, None)
        return [r[4][0] for r in results]
    except socket.gaierror:
        return []


def validate_scan_target(url: str) -> str:
    """
    Validate a scan target URL against SSRF rules.

    Raises HTTP 400 if the URL is invalid or resolves to a private/blocked address.
    Returns the normalised URL on success.
    """
    if not url or not isinstance(url, str):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_target", "message": "Scan target URL is required."},
        )

    url = url.strip()
    if len(url) > 2048:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_target", "message": "Target URL is too long."},
        )

    try:
        parsed = urlparse(url)
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_target", "message": "Could not parse the target URL."},
        )

    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "invalid_scheme",
                "message": f"Only http and https targets are supported. Got: '{parsed.scheme}'",
            },
        )

    hostname = parsed.hostname or ""
    if not hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_target", "message": "Target URL must contain a valid hostname."},
        )

    # Block known-bad hostnames before DNS resolution
    if hostname.lower() in _BLOCKED_HOSTNAMES:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "ssrf_blocked",
                "message": f"Scanning '{hostname}' is not permitted.",
            },
        )

    # If it looks like a raw IP, check it directly
    try:
        addr = ipaddress.ip_address(hostname)
        if _is_private(str(addr)):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "ssrf_blocked",
                    "message": "Scanning private/internal IP addresses is not permitted.",
                },
            )
        return url
    except ValueError:
        pass  # Not a raw IP — proceed to DNS resolution

    # DNS resolution SSRF check
    resolved = _resolve_hostname(hostname)
    if not resolved:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "dns_resolution_failed",
                "message": f"Could not resolve hostname: {hostname}",
            },
        )

    for ip in resolved:
        if _is_private(ip):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={
                    "error": "ssrf_blocked",
                    "message": f"'{hostname}' resolves to a private address. Scanning internal infrastructure is not permitted.",
                },
            )

    return url
