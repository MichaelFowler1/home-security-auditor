"""
External attack surface.

What does the internet see when looking at your home network? Without a VPS
to scan yourself from, we have two free options:
  1. Shodan InternetDB API (free, no key) - returns CVEs, open ports, hostnames
     for any IP it has indexed.
  2. ipinfo.io - confirms our public IP, ASN, geolocation (sanity check).

Optional: with a Shodan API key, deeper data including service banners and
historical scan data.

The result is a "view from outside" findings block.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from typing import Any

log = logging.getLogger(__name__)


def get_public_ip() -> str | None:
    """Find our public IP. ipify is the simplest free option."""
    try:
        with urllib.request.urlopen("https://api.ipify.org?format=json", timeout=10) as resp:
            return json.loads(resp.read()).get("ip")
    except Exception as e:
        log.warning(f"Public IP lookup failed: {e}")
        return None


def query_internetdb(ip: str) -> dict[str, Any] | None:
    """Shodan's free InternetDB. Returns ports, CVEs, hostnames seen."""
    try:
        req = urllib.request.Request(
            f"https://internetdb.shodan.io/{ip}",
            headers={"User-Agent": "SecAudit/1.0"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return {"indexed": False, "note": "Shodan has no record - likely good"}
        log.warning(f"InternetDB query failed: {e}")
        return None
    except Exception as e:
        log.warning(f"InternetDB query failed: {e}")
        return None


def query_shodan_host(ip: str, api_key: str) -> dict[str, Any] | None:
    """Full Shodan host lookup if user has an API key."""
    try:
        url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
        with urllib.request.urlopen(url, timeout=15) as resp:
            return json.loads(resp.read())
    except Exception as e:
        log.warning(f"Shodan host query failed: {e}")
        return None


def query_ipinfo(ip: str) -> dict[str, Any] | None:
    """ASN + geo info for context."""
    try:
        with urllib.request.urlopen(f"https://ipinfo.io/{ip}/json", timeout=10) as resp:
            return json.loads(resp.read())
    except Exception as e:
        log.warning(f"ipinfo query failed: {e}")
        return None


def audit_external_surface() -> dict[str, Any]:
    """Run all external checks."""
    findings: dict[str, Any] = {}

    public_ip = get_public_ip()
    findings["public_ip"] = public_ip
    if not public_ip:
        findings["error"] = "Could not determine public IP"
        return findings

    findings["ipinfo"] = query_ipinfo(public_ip)
    findings["shodan_internetdb"] = query_internetdb(public_ip)

    shodan_key = os.environ.get("SHODAN_API_KEY")
    if shodan_key:
        findings["shodan_full"] = query_shodan_host(public_ip, shodan_key)

    return findings
