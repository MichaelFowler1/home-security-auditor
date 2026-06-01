"""
Credential exposure.

Two checks:
  1. Find email addresses that show up in browser autofill / saved logins / OS
     account configuration, then query Have I Been Pwned to see which ones
     appear in known breaches.
  2. Locate browser credential stores (Chrome/Edge Login Data, Firefox logins.json)
     and report their existence + last modified time. We do NOT decrypt them —
     that requires DPAPI and feels like crossing a line even on the user's own box.

HIBP requires an API key for email lookups ($3.95/mo). If not configured we skip
that step and just report which emails we found.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import re
import subprocess
import time
import urllib.request
from typing import Any

log = logging.getLogger(__name__)

EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b")


def find_emails_on_system() -> set[str]:
    """
    Look in common places for email addresses associated with this user.
    We use PowerShell to read Windows-side data since the user's browsers and
    accounts live there.
    """
    ps = r"""
    $emails = New-Object System.Collections.Generic.HashSet[string]

    # Windows account email
    try {
        $accounts = Get-WmiObject -Class Win32_UserAccount -Filter "LocalAccount=True"
        foreach ($a in $accounts) {
            if ($a.FullName -match '[\w.+-]+@[\w-]+\.[\w.-]+') {
                $emails.Add($matches[0]) | Out-Null
            }
        }
    } catch {}

    # Outlook profile (if installed) - registry stores SMTP addresses
    try {
        $regPaths = @(
            'HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\*\*',
            'HKCU:\Software\Microsoft\Windows Messaging Subsystem\Profiles\*\*'
        )
        foreach ($p in $regPaths) {
            Get-ItemProperty $p -ErrorAction SilentlyContinue | ForEach-Object {
                $_ | Format-List | Out-String | ForEach-Object {
                    [regex]::Matches($_, '[\w.+-]+@[\w-]+\.[\w.-]+') | ForEach-Object {
                        $emails.Add($_.Value) | Out-Null
                    }
                }
            }
        }
    } catch {}

    # Git config
    try {
        $gitConfig = Get-Content "$env:USERPROFILE\.gitconfig" -ErrorAction SilentlyContinue
        if ($gitConfig) {
            [regex]::Matches(($gitConfig -join "`n"), '[\w.+-]+@[\w-]+\.[\w.-]+') | ForEach-Object {
                $emails.Add($_.Value) | Out-Null
            }
        }
    } catch {}

    $emails | ConvertTo-Json -Compress
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=60,
        )
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            if isinstance(data, str):
                return {data}
            return set(data)
    except Exception as e:
        log.warning(f"Email enumeration failed: {e}")
    return set()


def find_credential_stores() -> list[dict[str, Any]]:
    """
    Locate browser credential databases. We report path, size, and last-modified
    time only. Encryption status is just "yes" - all modern browsers use DPAPI.
    """
    ps = r"""
    $paths = @(
        @{ browser = 'Chrome';  path = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Login Data" },
        @{ browser = 'Edge';    path = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Login Data" },
        @{ browser = 'Brave';   path = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default\Login Data" },
        @{ browser = 'Firefox'; path = "$env:APPDATA\Mozilla\Firefox\Profiles" }
    )
    $found = @()
    foreach ($p in $paths) {
        if (Test-Path $p.path) {
            $item = Get-Item $p.path
            $found += @{
                browser   = $p.browser
                path      = $p.path
                last_mod  = $item.LastWriteTime.ToString('o')
                exists    = $true
                encrypted = $true
            }
        }
    }
    $found | ConvertTo-Json -Compress
    """
    try:
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-Command", ps],
            capture_output=True, text=True, timeout=30,
        )
        if proc.stdout.strip():
            data = json.loads(proc.stdout)
            if isinstance(data, dict):
                return [data]
            return data
    except Exception as e:
        log.warning(f"Credential store check failed: {e}")
    return []


def query_hibp(email: str, api_key: str) -> list[dict[str, Any]] | None:
    """Query Have I Been Pwned for breaches containing this email."""
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}?truncateResponse=false"
    try:
        req = urllib.request.Request(url, headers={
            "hibp-api-key": api_key,
            "User-Agent": "SecAudit/1.0",
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return []  # not in any breaches
        log.warning(f"HIBP query failed for {email}: {e}")
        return None
    except Exception as e:
        log.warning(f"HIBP query failed for {email}: {e}")
        return None


def audit_credentials() -> dict[str, Any]:
    """Run the credential exposure audit."""
    import urllib.parse  # noqa - imported here so the module imports cleanly without it at top

    findings: dict[str, Any] = {
        "emails_found_on_system": [],
        "credential_stores": find_credential_stores(),
        "breach_lookups": {},
    }

    emails = find_emails_on_system()
    findings["emails_found_on_system"] = sorted(emails)

    hibp_key = os.environ.get("HIBP_API_KEY")
    if hibp_key and emails:
        for email in sorted(emails):
            breaches = query_hibp(email, hibp_key)
            if breaches is not None:
                findings["breach_lookups"][email] = [
                    {
                        "name": b.get("Name"),
                        "domain": b.get("Domain"),
                        "breach_date": b.get("BreachDate"),
                        "data_classes": b.get("DataClasses"),
                        "is_verified": b.get("IsVerified"),
                    }
                    for b in breaches
                ]
            time.sleep(1.6)  # HIBP rate limit
    else:
        findings["hibp_note"] = "Set HIBP_API_KEY to enable breach lookups ($3.95/mo from haveibeenpwned.com)"

    return findings
