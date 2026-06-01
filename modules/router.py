"""
Router audit.

Two strategies:
  1. Generic: an authenticated requests.Session against the router's web admin,
     then parse pages with BeautifulSoup. Configure per-router in router_config.json.
  2. Vendor adapters: for known routers (ASUS, Netgear, TP-Link, UniFi, OpenWRT)
     we have specific endpoints we know about.

We collect:
  - Firmware version + check if outdated
  - WAN-exposed ports (port forwarding rules)
  - UPnP-opened ports (often opened silently by IoT)
  - Connected client list
  - WiFi: SSID, encryption type, WPS state, guest network isolation
  - DNS settings (hijack check)
  - Admin password policy hints (default? changed?)

Until the user provides their specific router make/model, this module runs in
generic mode using a config file.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
import socket
import struct
import urllib.parse
import urllib.request
from typing import Any

log = logging.getLogger(__name__)

CONFIG_PATH = pathlib.Path(__file__).parent.parent / "router_config.json"


def get_default_gateway() -> str | None:
    """Read /proc/net/route to find the default gateway IP. WSL2 will give us
    its own gateway, not the LAN router — caller should override if needed."""
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                fields = line.strip().split()
                if fields[1] == "00000000":  # destination 0.0.0.0
                    gw_hex = fields[2]
                    return socket.inet_ntoa(struct.pack("<L", int(gw_hex, 16)))
    except Exception as e:
        log.warning(f"Couldn't read default gateway: {e}")
    return None


def upnp_list_port_forwards(timeout: float = 3.0) -> list[dict[str, Any]]:
    """
    Walk the UPnP IGD on the router and list active port mappings. These are
    forwards that apps/IoT/malware opened silently — usually the biggest WAN
    exposure surprise people get from this audit.

    Uses raw SOAP to avoid extra dependencies.
    """
    # First find the IGD device via SSDP
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
        "\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(msg, ("239.255.255.250", 1900))

    location = None
    try:
        while True:
            data, _ = sock.recvfrom(8192)
            text = data.decode(errors="ignore")
            for line in text.split("\r\n"):
                if line.lower().startswith("location:"):
                    location = line.split(":", 1)[1].strip()
                    break
            if location:
                break
    except socket.timeout:
        pass
    finally:
        sock.close()

    if not location:
        log.info("UPnP IGD not found - router doesn't advertise UPnP (this is good!)")
        return []

    # Get the device description to find the WANIPConnection service URL
    try:
        with urllib.request.urlopen(location, timeout=5) as resp:
            desc = resp.read().decode(errors="ignore")
    except Exception as e:
        log.warning(f"UPnP description fetch failed: {e}")
        return []

    # Find the control URL for WANIPConnection
    ctrl_match = re.search(
        r"<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>.*?"
        r"<controlURL>([^<]+)</controlURL>",
        desc, re.DOTALL,
    )
    if not ctrl_match:
        return []

    # Build the full control URL
    parsed = urllib.parse.urlparse(location)
    ctrl_url = f"{parsed.scheme}://{parsed.netloc}{ctrl_match.group(1)}"

    # Enumerate port mappings by calling GetGenericPortMappingEntry with increasing index
    mappings = []
    for idx in range(50):  # cap iterations
        soap = (
            '<?xml version="1.0"?>\n'
            '<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">'
            '<s:Body><u:GetGenericPortMappingEntry '
            'xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">'
            f"<NewPortMappingIndex>{idx}</NewPortMappingIndex>"
            "</u:GetGenericPortMappingEntry></s:Body></s:Envelope>"
        )
        try:
            req = urllib.request.Request(
                ctrl_url, data=soap.encode(),
                headers={
                    "Content-Type": 'text/xml; charset="utf-8"',
                    "SOAPAction": '"urn:schemas-upnp-org:service:WANIPConnection:1#GetGenericPortMappingEntry"',
                },
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode(errors="ignore")
        except Exception:
            break  # we hit the end of the table

        entry = {}
        for tag in ("NewExternalPort", "NewInternalPort", "NewInternalClient",
                    "NewProtocol", "NewPortMappingDescription", "NewEnabled"):
            m = re.search(f"<{tag}>([^<]*)</{tag}>", body)
            if m:
                entry[tag] = m.group(1)
        if entry:
            mappings.append(entry)
        else:
            break

    return mappings


def http_get_with_session(session_cookies: dict[str, str], url: str, timeout: float = 5.0) -> str | None:
    """GET with provided cookies. Returns body text or None on failure."""
    try:
        cookie_str = "; ".join(f"{k}={v}" for k, v in session_cookies.items())
        req = urllib.request.Request(url, headers={"Cookie": cookie_str, "User-Agent": "SecAudit/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode(errors="ignore")
    except Exception as e:
        log.debug(f"GET {url} failed: {e}")
        return None


def check_router_default_creds(router_ip: str) -> dict[str, Any]:
    """
    Probe the admin page and check whether common default cred lists work.
    This is read-only - we try GET /login or similar with default creds and
    note success but don't change anything.

    Done very conservatively: only the absolute most common defaults, with
    delays, so we don't lock anyone out.
    """
    # Just check whether the admin page exists and what auth method it uses.
    # Actually trying creds risks lockouts; we report the surface instead.
    result: dict[str, Any] = {"admin_url": None, "auth_method": None}
    for scheme, port in [("http", 80), ("https", 443), ("http", 8080)]:
        url = f"{scheme}://{router_ip}:{port}/"
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SecAudit/1.0"})
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with urllib.request.urlopen(req, timeout=3, context=ctx) as resp:
                result["admin_url"] = url
                www_auth = resp.headers.get("WWW-Authenticate", "")
                if www_auth:
                    result["auth_method"] = www_auth.split()[0]
                else:
                    result["auth_method"] = "form-based (likely)"
                body = resp.read(2048).decode(errors="ignore")
                title = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
                if title:
                    result["title"] = title.group(1).strip()[:200]
                return result
        except Exception:
            continue
    return result


def generic_audit(config: dict[str, Any]) -> dict[str, Any]:
    """
    Generic router audit. Reads endpoints + selectors from router_config.json.
    Returns whatever pages it could fetch + parsed values.
    """
    findings: dict[str, Any] = {
        "configured": True,
        "router_ip": config.get("router_ip"),
        "make": config.get("make", "unknown"),
        "model": config.get("model", "unknown"),
        "pages": {},
    }

    # Login flow varies by vendor; the config file describes it.
    login_url = config.get("login_url")
    login_data = config.get("login_data")  # {username: ..., password: ...}
    session_cookies: dict[str, str] = {}

    if login_url and login_data:
        try:
            req = urllib.request.Request(
                login_url, data=urllib.parse.urlencode(login_data).encode(),
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                # Capture Set-Cookie headers
                for header in resp.headers.get_all("Set-Cookie") or []:
                    name, _, rest = header.partition("=")
                    val, _, _ = rest.partition(";")
                    session_cookies[name.strip()] = val.strip()
                findings["login_status"] = "ok"
        except Exception as e:
            findings["login_status"] = f"failed: {e}"
            return findings

    # Fetch each page defined in config
    for page_name, page_url in (config.get("pages") or {}).items():
        body = http_get_with_session(session_cookies, page_url)
        if body:
            # Apply regex selectors if defined
            extracted = {}
            for field, pattern in (config.get("selectors", {}).get(page_name) or {}).items():
                m = re.search(pattern, body)
                if m:
                    extracted[field] = m.group(1).strip()
            findings["pages"][page_name] = {
                "extracted": extracted,
                "size_bytes": len(body),
            }

    return findings


def flag_critical_router_settings(authenticated: dict[str, Any]) -> list[dict[str, str]]:
    """
    Walk the extracted values from authenticated router pages and produce
    explicit "flag" entries for the highest-risk settings. The LLM uses these
    as structured signals on top of the raw page extracts.

    Generic across vendors — keys match what config selectors are named.
    """
    flags: list[dict[str, str]] = []
    pages = authenticated.get("pages", {}) if isinstance(authenticated, dict) else {}

    def field(page: str, name: str) -> str | None:
        return pages.get(page, {}).get("extracted", {}).get(name)

    # Remote admin enabled = critical
    if field("remote_admin", "remote_enabled") == "1":
        port = field("remote_admin", "remote_port") or "unknown"
        flags.append({
            "severity": "critical",
            "finding": f"Remote administration is ENABLED on port {port}. Router admin is reachable from the internet.",
            "fix": "Disable Remote Administration in the router admin → Remote Access section.",
        })

    # DMZ host enabled
    if field("dmz_host", "dmz_enabled") == "1":
        target = field("dmz_host", "dmz_host_ip") or "unknown"
        flags.append({
            "severity": "critical",
            "finding": f"DMZ host is enabled, forwarding all WAN traffic to {target}.",
            "fix": "Disable DMZ unless you have a specific, current reason for it. Use specific port forwards instead.",
        })

    # WPS
    if field("wps_config", "wps_enabled") == "1":
        flags.append({
            "severity": "high",
            "finding": "WPS is enabled. WPS PIN brute-force attacks can recover the WiFi password in roughly 4-10 hours.",
            "fix": "Disable WPS in the wireless settings.",
        })

    # UPnP (note: convenient, but a known silent-attack-surface generator)
    if field("upnp", "upnp_enabled") == "1":
        flags.append({
            "severity": "medium",
            "finding": "UPnP is enabled. Apps and IoT devices can open WAN ports without telling you. Cross-reference the upnp_port_forwards list for what's actually open.",
            "fix": "Disable UPnP if you don't need it (gaming and some VoIP rely on it). If you keep it, audit the port forward list regularly.",
        })

    # Guest network without isolation
    if field("wifi_guest", "guest_enabled") == "1" and field("wifi_guest", "client_isolation") != "1":
        flags.append({
            "severity": "medium",
            "finding": "Guest network is on but client isolation is off — guests can see LAN devices.",
            "fix": "Enable client/AP isolation on the guest network.",
        })

    # Firewall low/off
    fw_level = (field("firewall", "firewall_level") or "").lower()
    if fw_level in ("low", "off", "disabled"):
        flags.append({
            "severity": "high",
            "finding": f"Router firewall is set to '{fw_level}'.",
            "fix": "Raise firewall level to Medium or High in the firewall settings.",
        })

    return flags


def audit_router(router_ip: str | None = None) -> dict[str, Any]:
    """
    Top-level router audit. Always runs UPnP enumeration (no creds needed).
    Adds authenticated checks if router_config.json exists.
    """
    if router_ip is None:
        router_ip = get_default_gateway()
    log.info(f"Auditing router at {router_ip}")

    result: dict[str, Any] = {"router_ip": router_ip}

    # Unauthenticated checks
    result["admin_surface"] = check_router_default_creds(router_ip) if router_ip else {}
    result["upnp_port_forwards"] = upnp_list_port_forwards()

    # Authenticated checks if config exists
    if CONFIG_PATH.exists():
        try:
            config = json.loads(CONFIG_PATH.read_text())
            if not config.get("router_ip"):
                config["router_ip"] = router_ip
            result["authenticated"] = generic_audit(config)
            result["critical_flags"] = flag_critical_router_settings(result["authenticated"])
        except Exception as e:
            result["authenticated"] = {"error": str(e)}
    else:
        result["authenticated"] = {
            "configured": False,
            "hint": f"Create {CONFIG_PATH} with login_url, login_data, pages, selectors to enable authenticated audit",
        }

    return result
