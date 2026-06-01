"""
CVE enrichment.

For every service nmap identifies with a version, query the NVD API to get
real CVEs with CVSS scores, and check whether public exploits exist.

Two data sources:
  - NVD JSON API 2.0 (free, no key required, rate-limited to 5 req / 30 sec without key)
  - searchsploit (offline ExploitDB mirror, if installed)

We cache results to disk so we don't hammer the API across runs.
"""

from __future__ import annotations

import json
import logging
import pathlib
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request
from typing import Any

log = logging.getLogger(__name__)

CACHE_DIR = pathlib.Path.home() / ".cache" / "security-auditor" / "cve"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
CACHE_TTL_DAYS = 7

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _cache_path(key: str) -> pathlib.Path:
    safe = re.sub(r"[^a-zA-Z0-9._-]", "_", key)
    return CACHE_DIR / f"{safe}.json"


def _cache_get(key: str) -> Any | None:
    path = _cache_path(key)
    if not path.exists():
        return None
    age_days = (time.time() - path.stat().st_mtime) / 86400
    if age_days > CACHE_TTL_DAYS:
        return None
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError:
        return None


def _cache_set(key: str, data: Any) -> None:
    _cache_path(key).write_text(json.dumps(data))


def query_nvd(product: str, version: str, max_results: int = 10) -> list[dict[str, Any]]:
    """
    Query NVD for CVEs affecting product:version. Returns a list of compact CVE
    dicts. Results are cached for 7 days.
    """
    if not product or not version:
        return []

    cache_key = f"nvd:{product}:{version}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    # Use keyword search; CPE matching is more precise but harder to get right
    # when nmap gives us non-canonical product strings.
    query = f"{product} {version}"
    params = {"keywordSearch": query, "resultsPerPage": str(max_results)}
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"

    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SecAudit/1.0"})
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        log.warning(f"NVD query failed for {product} {version}: {e}")
        _cache_set(cache_key, [])  # cache the failure briefly too
        return []

    cves = []
    for item in data.get("vulnerabilities", [])[:max_results]:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # CVSS score - prefer v3.1 > v3.0 > v2
        metrics = cve.get("metrics", {})
        score = None
        severity = None
        vector = None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0]
                cvss = m.get("cvssData", {})
                score = cvss.get("baseScore")
                severity = cvss.get("baseSeverity") or m.get("baseSeverity")
                vector = cvss.get("vectorString")
                break

        # Get English description
        descriptions = cve.get("descriptions", [])
        desc = next(
            (d["value"] for d in descriptions if d.get("lang") == "en"),
            "",
        )

        cves.append({
            "id": cve_id,
            "score": score,
            "severity": severity,
            "vector": vector,
            "description": desc[:500],
            "published": cve.get("published", ""),
        })

    _cache_set(cache_key, cves)
    # Be polite to NVD's rate limit
    time.sleep(6)
    return cves


def searchsploit_lookup(product: str, version: str) -> list[dict[str, str]]:
    """
    If searchsploit is installed, look up public exploits. Returns list of
    {title, path, type}. The presence of a Metasploit module or PoC is a big
    signal that an attacker doesn't even need to know what they're doing.
    """
    if shutil.which("searchsploit") is None:
        return []

    cache_key = f"esp:{product}:{version}"
    cached = _cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        proc = subprocess.run(
            ["searchsploit", "--json", f"{product} {version}"],
            capture_output=True, text=True, timeout=30,
        )
        data = json.loads(proc.stdout) if proc.stdout else {}
        exploits = data.get("RESULTS_EXPLOIT", [])
        compact = [
            {
                "title": e.get("Title", ""),
                "type": e.get("Type", ""),
                "platform": e.get("Platform", ""),
                "path": e.get("Path", ""),
            }
            for e in exploits[:10]
        ]
        _cache_set(cache_key, compact)
        return compact
    except Exception as e:
        log.warning(f"searchsploit failed: {e}")
        return []


def enrich_with_cves(hosts: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Add CVE data to each port that has a product+version identified."""
    total_queries = sum(
        1 for h in hosts for p in h.get("open_ports", [])
        if p.get("product") and p.get("version")
    )
    log.info(f"Running CVE enrichment for {total_queries} service/version pairs...")

    for host in hosts:
        for port in host.get("open_ports", []):
            product = port.get("product")
            version = port.get("version")
            if not product or not version:
                continue

            cves = query_nvd(product, version)
            if cves:
                port["cves"] = cves
                # Flag the worst one for easy summary
                worst = max(
                    (c for c in cves if c.get("score") is not None),
                    key=lambda c: c["score"],
                    default=None,
                )
                if worst:
                    port["worst_cve"] = worst

            exploits = searchsploit_lookup(product, version)
            if exploits:
                port["public_exploits"] = exploits

    return hosts
