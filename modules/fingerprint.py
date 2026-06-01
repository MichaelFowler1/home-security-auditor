"""
Device fingerprinting.

Goes beyond nmap's basic OS guess. Combines:
  - MAC OUI lookup (vendor)
  - mDNS / Bonjour (Apple, Chromecast, printers)
  - SSDP / UPnP (smart TVs, IoT, media servers)
  - HTTP banner / title (admin pages, web UIs)
  - Hostname patterns (RING-..., HP-Printer-..., etc.)

Output: per-host device classification + the attack profile that applies to it.
"""

from __future__ import annotations

import json
import re
import socket
import subprocess
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import logging
log = logging.getLogger(__name__)


# Common IoT/consumer device patterns. The LLM will refine these per-host,
# but having a baseline classification helps us pick the right attack profile.
DEVICE_PATTERNS = {
    "ip_camera":   [r"camera", r"ipcam", r"hikvision", r"dahua", r"reolink", r"wyze", r"axis", r"foscam"],
    "smart_tv":    [r"roku", r"chromecast", r"samsung-tv", r"lgtv", r"appletv", r"firetv", r"bravia", r"webos"],
    "printer":     [r"hp[-_]?print", r"canon", r"epson", r"brother", r"officejet", r"laserjet", r"deskjet"],
    "nas":         [r"synology", r"qnap", r"freenas", r"truenas", r"netgear[-_]?readynas", r"diskstation"],
    "router":      [r"asus", r"netgear", r"tp[-_]?link", r"linksys", r"ubiquiti", r"unifi", r"openwrt", r"ddwrt"],
    "smart_speaker":[r"echo", r"alexa", r"google[-_]?home", r"nest[-_]?mini", r"sonos", r"homepod"],
    "phone":       [r"iphone", r"android", r"galaxy", r"pixel", r"oneplus"],
    "thermostat":  [r"nest", r"ecobee", r"honeywell"],
    "doorbell":    [r"ring", r"doorbell", r"arlo"],
    "game_console":[r"playstation", r"ps[345]", r"xbox", r"nintendo", r"switch"],
    "hub":         [r"smartthings", r"hubitat", r"hue[-_]?bridge", r"wink"],
}

# Attack profiles per device class. These are the playbooks an attacker on the LAN
# would actually run against each device type. The LLM uses these as context.
ATTACK_PROFILES = {
    "ip_camera": {
        "common_attacks": [
            "default credentials (admin/admin, admin/12345, root/pass)",
            "RTSP stream hijack on tcp/554 without auth",
            "ONVIF abuse on tcp/80 or 8000",
            "unpatched firmware CVEs - Hikvision, Dahua, Reolink all have wormable RCEs",
            "telnet/SSH backdoors left on by vendor",
        ],
        "pivot_value": "high - cameras often have weak isolation, run old Linux, and are always-on footholds",
        "common_ports": [80, 554, 1935, 8000, 8080, 8888, 9999, 37777],
    },
    "smart_tv": {
        "common_attacks": [
            "ADB over network on tcp/5555 (Android TV / Fire TV)",
            "DIAL protocol on tcp/8060/8008 - app injection",
            "Samsung remote control protocol abuse",
            "outdated WebKit / browser engines",
        ],
        "pivot_value": "medium - always-on, network-attached microphone in some cases",
        "common_ports": [5555, 7676, 8001, 8008, 8060, 9197],
    },
    "printer": {
        "common_attacks": [
            "PJL/PostScript filesystem access - dump stored print jobs and saved credentials",
            "SNMP public community string - leak network info",
            "default web admin (no auth or admin/blank)",
            "LDAP/SMB creds stored in plain text for scan-to-folder features",
        ],
        "pivot_value": "very high - printers hoard creds and are rarely patched",
        "common_ports": [80, 443, 515, 631, 9100, 161],
    },
    "nas": {
        "common_attacks": [
            "DSM/QTS web admin CVEs - frequent RCEs in last 3 years",
            "SMB/AFP shares with guest access",
            "exposed admin port forwarded via UPnP",
            "default admin account left enabled alongside personal account",
        ],
        "pivot_value": "critical - contains all your data, often runs as root",
        "common_ports": [22, 80, 443, 445, 5000, 5001, 5005, 5006],
    },
    "router": {
        "common_attacks": [
            "default admin credentials",
            "WPS PIN brute force (~6 hours if enabled)",
            "outdated firmware with known CVEs",
            "DNS hijack via admin compromise",
            "UPnP exploited by malware on LAN to open WAN ports silently",
        ],
        "pivot_value": "critical - controls all traffic, MITM position",
        "common_ports": [22, 23, 53, 80, 443, 8080, 8443],
    },
    "smart_speaker": {
        "common_attacks": [
            "voice command injection from nearby audio",
            "outdated firmware",
            "companion-app credential reuse",
        ],
        "pivot_value": "low-medium - sandboxed but always-listening",
        "common_ports": [4070, 8009, 55442, 55443],
    },
    "thermostat": {
        "common_attacks": [
            "cloud API token theft from companion app",
            "local API on tcp/80 without auth (older Nest, ecobee)",
        ],
        "pivot_value": "low - limited compute, but physical-world impact",
        "common_ports": [80, 443, 9543],
    },
    "doorbell": {
        "common_attacks": [
            "WiFi deauth -> capture handshake during reconnect",
            "cloud account takeover via credential stuffing",
        ],
        "pivot_value": "low-medium - mostly cloud-dependent",
        "common_ports": [80, 443],
    },
    "game_console": {
        "common_attacks": [
            "UPnP port forwards opened automatically (NAT type Open)",
            "outdated browser engines in console UI",
        ],
        "pivot_value": "low - locked down OS",
        "common_ports": [80, 443, 3074, 3478, 3479, 3480],
    },
    "hub": {
        "common_attacks": [
            "local API unauthenticated on LAN (Hue, older SmartThings)",
            "Zigbee/Z-Wave network key extraction",
        ],
        "pivot_value": "medium - controls many downstream devices",
        "common_ports": [80, 443, 8080, 8123],
    },
    "unknown": {
        "common_attacks": ["unidentified device - manual investigation recommended"],
        "pivot_value": "unknown",
        "common_ports": [],
    },
}


def classify_device(host: dict[str, Any]) -> str:
    """Pick the best device class given everything we know about the host."""
    haystack_parts = [
        host.get("hostname") or "",
        host.get("vendor") or "",
        host.get("mdns_name") or "",
        host.get("upnp_server") or "",
        host.get("http_title") or "",
    ]
    haystack = " ".join(haystack_parts).lower()

    for device_class, patterns in DEVICE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, haystack):
                return device_class

    # Port-based fallback
    ports = {p["port"] for p in host.get("open_ports", [])}
    if {554, 8000} & ports or 37777 in ports:
        return "ip_camera"
    if 9100 in ports:
        return "printer"
    if {5000, 5001} & ports:
        return "nas"
    if 8060 in ports or 5555 in ports:
        return "smart_tv"

    return "unknown"


def mdns_probe(ip: str, timeout: float = 2.0) -> str | None:
    """Reverse DNS lookup via mDNS. Best-effort."""
    try:
        socket.setdefaulttimeout(timeout)
        name, _, _ = socket.gethostbyaddr(ip)
        return name
    except (socket.herror, socket.gaierror, socket.timeout):
        return None


def ssdp_discover(timeout: float = 3.0) -> dict[str, dict[str, str]]:
    """
    Send a single SSDP M-SEARCH and collect responses. Returns {ip: {server, st, location}}.
    """
    msg = (
        "M-SEARCH * HTTP/1.1\r\n"
        "HOST: 239.255.255.250:1900\r\n"
        'MAN: "ssdp:discover"\r\n'
        "MX: 2\r\n"
        "ST: ssdp:all\r\n"
        "\r\n"
    ).encode()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    sock.sendto(msg, ("239.255.255.250", 1900))

    found: dict[str, dict[str, str]] = {}
    try:
        while True:
            data, addr = sock.recvfrom(8192)
            text = data.decode(errors="ignore")
            entry: dict[str, str] = {}
            for line in text.split("\r\n"):
                if ":" in line:
                    key, _, val = line.partition(":")
                    entry[key.strip().lower()] = val.strip()
            if addr[0] not in found:
                found[addr[0]] = entry
    except socket.timeout:
        pass
    finally:
        sock.close()

    return found


def http_probe(ip: str, port: int, timeout: float = 3.0) -> dict[str, str] | None:
    """Grab HTTP server header and <title>. Best-effort."""
    scheme = "https" if port in (443, 8443) else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 SecAudit"})
        # Disable SSL verification for self-signed home devices
        import ssl
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            body = resp.read(4096).decode(errors="ignore")
            server = resp.headers.get("Server", "")
            title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
            title = title_match.group(1).strip() if title_match else ""
            return {"server": server, "title": title[:200]}
    except Exception:
        return None


def enrich_hosts(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add fingerprinting data to each nmap host."""
    log.info("Running SSDP discovery...")
    ssdp_results = ssdp_discover()
    log.info(f"SSDP found {len(ssdp_results)} devices")

    def enrich_one(host: dict[str, Any]) -> dict[str, Any]:
        ip = host["ip"]

        # mDNS reverse lookup if hostname is missing
        if not host.get("hostname"):
            host["mdns_name"] = mdns_probe(ip)

        # SSDP server string
        if ip in ssdp_results:
            host["upnp_server"] = ssdp_results[ip].get("server", "")
            host["upnp_st"] = ssdp_results[ip].get("st", "")

        # Probe HTTP/HTTPS on common admin ports
        for port_info in host.get("open_ports", []):
            port = port_info["port"]
            if port in (80, 443, 8080, 8443, 8000, 8888):
                probe = http_probe(ip, port)
                if probe:
                    host["http_server"] = probe["server"]
                    host["http_title"] = probe["title"]
                    break

        # Classify and attach attack profile
        device_class = classify_device(host)
        host["device_class"] = device_class
        host["attack_profile"] = ATTACK_PROFILES.get(device_class, ATTACK_PROFILES["unknown"])
        return host

    enriched = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(enrich_one, h): h for h in hosts}
        for future in as_completed(futures):
            try:
                enriched.append(future.result(timeout=30))
            except Exception as e:
                log.warning(f"Enrich failed: {e}")
                enriched.append(futures[future])

    return enriched
