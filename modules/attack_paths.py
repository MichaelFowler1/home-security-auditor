"""
Attack path synthesis.

This is the module that makes the auditor feel like an ethical hacker rather
than a checklist tool. It takes ALL findings (network, devices, CVEs, router,
wireless, credentials, external surface) and asks GPT-5.5 to produce two
deliverables:

  1. Realistic kill chains: numbered attack narratives showing how an attacker
     would actually chain weaknesses together to reach a goal (your data, your
     accounts, persistence).

  2. Per-device threat model: for each device on the LAN, the realistic attacker
     playbook tailored to that specific device + its observed state.

The prompt is deliberately structured to make GPT-5.5 think like a pentester
- starting from attacker capabilities, working through the kill chain, and
ending with the specific defensive control that breaks each step.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from typing import Any

log = logging.getLogger(__name__)


ATTACK_SYNTHESIS_PROMPT = """You are a senior penetration tester writing a threat report for a homeowner who has run a defensive audit on their own network. Your goal is to make them genuinely understand HOW an attacker would compromise them, not just give them a checklist.

You will receive a structured JSON document containing:
  - Network scan: every device on the LAN, open ports, service versions
  - Device fingerprinting: device class (camera, NAS, printer, etc.) and known attack profiles
  - CVE data: real NVD CVEs against discovered services, with CVSS scores and whether public exploits exist
  - Router state: WAN exposure, UPnP-opened port forwards, admin surface
  - Wireless: connected SSID, encryption, nearby networks, saved profiles
  - Windows host: Defender, firewall, SMB config, accounts, listening ports, installed software, pending updates
  - Credential exposure: emails on the system, breach data if available
  - External attack surface: what Shodan / public scanners see from the internet

Produce a Markdown report with these sections, in this order:

## 1. Executive Summary
One paragraph. State the single biggest risk in plain English. If everything is fine, say so directly.

## 2. The Three Most Realistic Attack Paths
Pick the three most plausible kill chains an attacker would actually run against THIS specific environment. For each:

### Attack Path N: [Name it - e.g. "Pivot from outdated NAS to Windows host"]
- **Attacker starting position:** (e.g., "Internet-based, no prior access" or "On the LAN via WiFi" or "Already compromised one IoT device")
- **Why this is the path of least resistance for this network:** one sentence
- **Step-by-step kill chain:**
  1. Initial access: how they get in. Reference the specific CVE, misconfig, or default cred.
  2. Discovery: what they enumerate next.
  3. Lateral movement: how they pivot between devices, citing specific protocols/ports observed in the findings.
  4. Escalation: how they get higher privileges.
  5. Objective: what they accomplish (your data, persistence, your accounts, etc.)
- **Where the chain breaks:** the single defensive control that would stop this attack cold. Be specific - exact setting, command, or device replacement.
- **Effort to fix:** Low / Medium / High

## 3. Per-Device Threat Model
For EACH discovered device on the LAN, give:
- Device name + IP + classification
- The realistic attacker playbook for this specific device given its observed state
- The 1-3 things you'd change today

Skip devices that are well-secured - just list them at the end as "Low concern: ..."

## 4. Critical CVEs Found
If real CVEs with CVSS >= 7.0 were found against actual running services, list them. Include:
- CVE-ID, CVSS score, affected device
- Whether public exploit code exists (huge difference between "theoretical" and "metasploit module exists")
- The specific upgrade or mitigation

## 5. Router & Perimeter
Findings about the router, UPnP exposure, WiFi, external surface. Emphasize any internet-exposed ports - this is the single highest-leverage area.

## 6. The Patches In Priority Order
A numbered list, 5-15 items, ordered by risk reduction per minute of work. For each: what to do, where (exact location/command), and which attack path above it kills.

## 7. False Positives To Ignore
nmap's vuln scripts have well-known false positives (http-slowloris on devices that aren't actually vulnerable, http-csrf on every admin page, etc). Call out anything in the findings that looks scary but isn't.

# Writing rules
- Talk to the homeowner directly. Use "you" and "your".
- No corporate or "as an AI" filler.
- Be specific. "Update your router firmware" is bad. "Your TP-Link Archer C7 is on firmware 3.15.3, June 2023; upgrade to the latest at tp-link.com/support/download/archer-c7/" is good. If you don't have enough info to be specific, ask the homeowner to provide it.
- When you cite a CVE or attack technique, be confident if the evidence is in the findings. Hedge if you're inferring.
- Severity grading should match real-world exploitability. A CVE with a public Metasploit module on an internet-exposed service is critical. The same CVE on a LAN-only device behind a router is high or medium. A theoretical CVE with no PoC on an unused service is low.
- It's OK to be reassuring if the findings warrant it. Don't manufacture urgency."""


def call_openai_for_attack_paths(all_findings: dict[str, Any]) -> str:
    """Send the complete findings dict to GPT-5.5 and get the kill-chain report."""
    try:
        from openai import OpenAI
    except ImportError:
        sys.exit("pip install openai")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        sys.exit("Set OPENAI_API_KEY")

    payload = json.dumps(all_findings, indent=2, default=str)

    # Cap at ~150k chars (~40k tokens). GPT-5.5 can handle more but cost goes up.
    max_chars = 150_000
    if len(payload) > max_chars:
        log.warning(f"Findings payload {len(payload)} chars, truncating to {max_chars}")
        payload = payload[:max_chars] + "\n\n...[truncated for size]"

    client = OpenAI(api_key=api_key)
    log.info(f"Calling gpt-5.5 with {len(payload)} chars of findings (high reasoning)...")

    resp = client.responses.create(
        model="gpt-5.5",
        reasoning={"effort": "high"},
        input=[
            {"role": "system", "content": ATTACK_SYNTHESIS_PROMPT},
            {
                "role": "user",
                "content": (
                    "Here is the complete audit data. Produce the threat report.\n\n"
                    f"```json\n{payload}\n```"
                ),
            },
        ],
    )
    return resp.output_text
