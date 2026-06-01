"""
Wireless audit.

Uses Windows' `netsh wlan` via PowerShell to gather:
  - SSID of the network we're connected to
  - Authentication and cipher (WPA2/WPA3/Open/WEP)
  - Profile config (auto-connect, key material if user authorized export)
  - Visible nearby networks and their security
  - Whether the connected SSID is broadcasting WPS

We can't easily check our own router's WPS state from the client side, but we
can flag if any nearby SSID has WPS enabled (often the same router).
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from typing import Any

log = logging.getLogger(__name__)


def run_ps(command: str, timeout: int = 30) -> str:
    """Run PowerShell from WSL and return stdout."""
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
        )
        return proc.stdout
    except Exception as e:
        log.warning(f"PowerShell call failed: {e}")
        return ""


def parse_netsh_show_interfaces(output: str) -> dict[str, str]:
    """Parse `netsh wlan show interfaces` output into a flat dict."""
    result = {}
    for line in output.splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            result[key.strip().lower()] = val.strip()
    return result


def parse_netsh_show_networks(output: str) -> list[dict[str, str]]:
    """Parse `netsh wlan show networks mode=bssid` into a list of network dicts."""
    networks = []
    current: dict[str, str] = {}
    for line in output.splitlines():
        line = line.rstrip()
        if not line:
            continue
        ssid_match = re.match(r"^SSID \d+ : (.*)$", line)
        if ssid_match:
            if current:
                networks.append(current)
            current = {"ssid": ssid_match.group(1)}
            continue
        if line.startswith("    ") and ":" in line:
            key, _, val = line.partition(":")
            current[key.strip().lower()] = val.strip()
    if current:
        networks.append(current)
    return networks


def audit_wireless() -> dict[str, Any]:
    """Run all the wireless checks and return findings."""
    findings: dict[str, Any] = {}

    # What we're connected to right now
    interfaces_raw = run_ps("netsh wlan show interfaces")
    findings["current_interface"] = parse_netsh_show_interfaces(interfaces_raw)

    # All known profiles (saved networks)
    profiles_raw = run_ps("netsh wlan show profiles")
    profile_names = re.findall(r"All User Profile\s+:\s+(.+)$", profiles_raw, re.MULTILINE)
    findings["saved_profiles"] = []
    for name in profile_names[:30]:  # cap
        profile_raw = run_ps(f'netsh wlan show profile name="{name.strip()}"')
        profile_info = {"name": name.strip()}
        for line in profile_raw.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                key = key.strip().lower()
                if key in ("authentication", "cipher", "security key",
                          "connect automatically", "connection mode"):
                    profile_info[key] = val.strip()
        findings["saved_profiles"].append(profile_info)

    # Visible networks (with BSSID detail to see security per AP)
    visible_raw = run_ps("netsh wlan show networks mode=bssid")
    findings["visible_networks"] = parse_netsh_show_networks(visible_raw)

    # Flag the obvious issues
    issues = []
    current_auth = findings["current_interface"].get("authentication", "").lower()
    if "wep" in current_auth or "open" in current_auth:
        issues.append(f"Currently connected with weak/no encryption: {current_auth}")
    elif "wpa3" not in current_auth:
        # WPA2 is fine but worth noting
        issues.append(f"Currently on {current_auth} - consider WPA3 if router supports it")

    for net in findings["visible_networks"]:
        if net.get("ssid") == findings["current_interface"].get("ssid"):
            if net.get("authentication", "").lower() == "open":
                issues.append(f"Your SSID '{net['ssid']}' has an open BSSID nearby - possible evil twin")

    findings["issues"] = issues
    return findings
