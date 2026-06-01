#!/usr/bin/env python3
"""
Home network ethical-hacker auditor.

Combines:
  - nmap network scanning + vuln scripts
  - Device fingerprinting (mDNS, SSDP/UPnP, HTTP banners)
  - CVE enrichment from NVD + ExploitDB
  - Windows host audit (Defender, firewall, SMB, accounts, updates, software)
  - Router audit (UPnP-opened ports, admin surface, authenticated checks if configured)
  - Wireless audit (netsh wlan)
  - Credential exposure (emails on system, HIBP if configured)
  - External attack surface (Shodan InternetDB)
  - GPT-5.5 kill-chain synthesis

Usage:
    export OPENAI_API_KEY=sk-...
    python3 security_audit.py                    # full audit
    python3 security_audit.py --quick            # nmap discovery only, skip vuln scripts
    python3 security_audit.py --host-only        # Windows + router + wireless, no LAN scan
    python3 security_audit.py --no-llm           # collect everything, skip the report
    python3 security_audit.py --subnet 192.168.1.0/24
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import logging
import os
import pathlib
import re
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any

from modules import fingerprint, cve, router, wireless, credentials, external, attack_paths

# --- Setup --------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("audit")

REPORTS_DIR = pathlib.Path.home() / "security-audit-reports"
SCRIPT_DIR = pathlib.Path(__file__).resolve().parent
PS_SCRIPT = SCRIPT_DIR / "windows_audit.ps1"


def require(tool: str, install_hint: str) -> None:
    if shutil.which(tool) is None:
        sys.exit(f"Missing required tool: {tool}\n  {install_hint}")


# --- Subnet detection ---------------------------------------------------------

def detect_subnet() -> str:
    """Use Windows PowerShell to find the real LAN IP (WSL2's own IP is NAT'd)."""
    ps = (
        "Get-NetIPConfiguration | "
        "Where-Object { $_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -eq 'Up' } | "
        "Select-Object -First 1 -ExpandProperty IPv4Address | "
        "Select-Object -ExpandProperty IPAddress"
    )
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", ps],
        capture_output=True, text=True, timeout=30,
    )
    ip = proc.stdout.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        sys.exit(f"Could not detect LAN IP from Windows: {proc.stdout!r} {proc.stderr!r}")
    network = ipaddress.ip_network(f"{ip}/24", strict=False)
    log.info(f"Detected Windows LAN IP {ip}, scanning subnet {network}")
    return str(network)


# --- nmap ---------------------------------------------------------------------

def nmap_scan(subnet: str, quick: bool) -> dict[str, Any]:
    require("nmap", "sudo apt install nmap")
    if quick:
        args = ["nmap", "-sn", subnet, "-oX", "-"]
    else:
        args = ["nmap", "-T4", "-sV", "-O", "--script", "vuln", "-oX", "-", subnet]

    log.info(f"Running nmap{' (quick)' if quick else ' (full + vuln scripts)'} on {subnet}...")
    proc = subprocess.run(args, capture_output=True, text=True, timeout=3600)
    if proc.returncode != 0:
        log.warning(f"nmap returncode {proc.returncode}: {proc.stderr[:500]}")
    return parse_nmap_xml(proc.stdout)


def parse_nmap_xml(xml_text: str) -> dict[str, Any]:
    if not xml_text.strip():
        return {"hosts": [], "error": "empty nmap output"}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        return {"hosts": [], "error": f"parse: {e}"}

    hosts = []
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue

        ipv4 = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "ipv4"), None)
        mac = next((a.get("addr") for a in host.findall("address") if a.get("addrtype") == "mac"), None)
        vendor = next((a.get("vendor") for a in host.findall("address") if a.get("addrtype") == "mac"), None)
        hostname_el = host.find("hostnames/hostname")
        hostname = hostname_el.get("name") if hostname_el is not None else None

        # OS guess
        os_match = host.find("os/osmatch")
        os_guess = os_match.get("name") if os_match is not None else None

        ports = []
        for port in host.findall("ports/port"):
            state = port.find("state")
            if state is None or state.get("state") != "open":
                continue
            svc = port.find("service")
            scripts = []
            for script in port.findall("script"):
                output = (script.get("output") or "").strip()
                if output and not output.startswith("ERROR"):
                    scripts.append({"id": script.get("id"), "output": output[:2000]})
            ports.append({
                "port": int(port.get("portid")),
                "protocol": port.get("protocol"),
                "service": svc.get("name") if svc is not None else None,
                "product": svc.get("product") if svc is not None else None,
                "version": svc.get("version") if svc is not None else None,
                "scripts": scripts,
            })

        hosts.append({
            "ip": ipv4,
            "mac": mac,
            "vendor": vendor,
            "hostname": hostname,
            "os_guess": os_guess,
            "open_ports": ports,
        })

    return {"hosts": hosts, "scanned_at": dt.datetime.now().isoformat()}


# --- Windows host audit -------------------------------------------------------

def windows_audit() -> dict[str, Any]:
    if not PS_SCRIPT.exists():
        return {"error": f"missing {PS_SCRIPT}"}
    win_path = subprocess.check_output(["wslpath", "-w", str(PS_SCRIPT)], text=True).strip()
    proc = subprocess.run(
        ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", win_path],
        capture_output=True, text=True, timeout=600,
    )
    if not proc.stdout.strip():
        return {"error": "no output from PowerShell", "stderr": proc.stderr[:1000]}
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as e:
        return {"error": f"json parse: {e}", "raw": proc.stdout[:2000]}


# --- Reporting ----------------------------------------------------------------

def write_report(report_md: str, raw_findings: dict[str, Any]) -> pathlib.Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    md_path = REPORTS_DIR / f"audit_{stamp}.md"
    json_path = REPORTS_DIR / f"audit_{stamp}.json"

    md_path.write_text(f"# Security Audit — {stamp}\n\n{report_md}\n")
    json_path.write_text(json.dumps(raw_findings, indent=2, default=str))

    latest = REPORTS_DIR / "latest.json"
    if latest.exists():
        latest.rename(REPORTS_DIR / "previous.json")
    latest.write_text(json.dumps(raw_findings, indent=2, default=str))

    return md_path


# --- Main ---------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--subnet", help="Override autodetected subnet")
    ap.add_argument("--quick", action="store_true", help="Skip nmap vuln scripts")
    ap.add_argument("--host-only", action="store_true", help="Skip LAN scan")
    ap.add_argument("--no-llm", action="store_true", help="Skip GPT-5.5 synthesis")
    ap.add_argument("--skip-cve", action="store_true", help="Skip NVD CVE enrichment (faster)")
    ap.add_argument("--skip-external", action="store_true", help="Skip Shodan/external checks")
    args = ap.parse_args()

    findings: dict[str, Any] = {
        "started_at": dt.datetime.now().isoformat(),
        "metadata": {
            "tool_version": "2.0",
            "host_machine": "WSL2 + Windows",
        },
    }

    # ---- Network scan + enrichment ----
    if not args.host_only:
        subnet = args.subnet or detect_subnet()
        findings["subnet"] = subnet
        scan = nmap_scan(subnet, quick=args.quick)
        log.info(f"nmap found {len(scan.get('hosts', []))} hosts")

        log.info("Enriching hosts with device fingerprinting...")
        scan["hosts"] = fingerprint.enrich_hosts(scan["hosts"])

        if not args.skip_cve and not args.quick:
            log.info("Enriching with CVE data from NVD...")
            scan["hosts"] = cve.enrich_with_cves(scan["hosts"])

        findings["network_scan"] = scan

    # ---- Router audit ----
    log.info("Auditing router...")
    findings["router"] = router.audit_router()

    # ---- Wireless ----
    log.info("Auditing wireless...")
    findings["wireless"] = wireless.audit_wireless()

    # ---- Windows host ----
    log.info("Auditing Windows host...")
    findings["windows_host"] = windows_audit()

    # ---- Credentials ----
    log.info("Checking credential exposure...")
    findings["credentials"] = credentials.audit_credentials()

    # ---- External surface ----
    if not args.skip_external:
        log.info("Checking external attack surface...")
        findings["external_surface"] = external.audit_external_surface()

    findings["completed_at"] = dt.datetime.now().isoformat()

    # ---- LLM synthesis ----
    if args.no_llm:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        out = REPORTS_DIR / "findings_only.json"
        out.write_text(json.dumps(findings, indent=2, default=str))
        log.info(f"Wrote raw findings to {out}")
        return

    log.info("Synthesizing attack paths with gpt-5.5...")
    report = attack_paths.call_openai_for_attack_paths(findings)
    report_path = write_report(report, findings)

    log.info(f"\n{'=' * 60}\nReport written to: {report_path}\n{'=' * 60}")
    # Print first ~3KB to stdout so the user gets immediate value
    print("\n" + report[:3000])
    if len(report) > 3000:
        print(f"\n...[truncated - see {report_path} for the full report]")


if __name__ == "__main__":
    main()
