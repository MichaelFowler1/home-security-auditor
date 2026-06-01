# Home Network Ethical-Hacker Auditor v2

Models how an attacker would actually compromise your home network and produces a kill-chain report with specific remediation. Read-only — never executes attacks, never changes settings.

## What it does

| Module | What it collects |
|--------|------------------|
| **nmap network scan** | Every live host on your LAN, open ports, service versions, nmap's `vuln` script results |
| **Device fingerprinting** | mDNS, SSDP/UPnP, HTTP banners → classifies each device (camera, NAS, printer, etc.) and attaches the realistic attack playbook for that device class |
| **CVE enrichment** | Queries NVD for real CVEs against every product+version nmap finds. Cross-references searchsploit/ExploitDB for public exploit code |
| **Router audit** | Default-gateway probe, UPnP-opened port forwards (the silent attack surface most people don't know about), admin web surface. Authenticated scrape if you supply `router_config.json` |
| **Wireless audit** | `netsh wlan` — current SSID encryption, saved profiles, visible networks, evil-twin detection |
| **Windows host audit** | Defender, firewall, SMBv1, accounts, pending updates, UAC, BitLocker, startup, listening ports, installed software, RDP |
| **Credential exposure** | Emails found in Windows accounts / Outlook / git config, optional Have I Been Pwned breach lookup, browser credential store locations |
| **External surface** | Your public IP, ASN, what Shodan's free InternetDB sees from the internet looking back at you |
| **GPT-5.5 synthesis** | Takes everything above and writes: 3 realistic kill chains, per-device threat model, prioritized patch list |

## Setup

In WSL2:

```bash
# Tools
sudo apt update
sudo apt install -y nmap python3-pip exploitdb   # exploitdb is optional but useful
pip3 install --user openai

# API keys
echo 'export OPENAI_API_KEY=sk-...' >> ~/.bashrc
# Optional:
# echo 'export HIBP_API_KEY=...' >> ~/.bashrc       # $3.95/mo, enables breach lookups
# echo 'export SHODAN_API_KEY=...' >> ~/.bashrc     # free tier works
source ~/.bashrc

# Permission for PowerShell scripts (run once, in Windows PowerShell as Admin)
# Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

## Usage

```bash
# Fast first run — discovers what's on the network, skips heavy scans
python3 security_audit.py --quick

# Full audit — the real deal. 20-60 minutes depending on LAN size
python3 security_audit.py

# Skip the LAN scan (just Windows + router + wireless + creds + external)
python3 security_audit.py --host-only

# Collect everything but skip the OpenAI call (free)
python3 security_audit.py --no-llm

# Speed up by skipping NVD lookups
python3 security_audit.py --skip-cve
```

Reports land in `~/security-audit-reports/`:
- `audit_<timestamp>.md` — the kill-chain report (what you read)
- `audit_<timestamp>.json` — raw findings (for diffing/automation)
- `latest.json` / `previous.json` — last two runs for change detection

## Router authenticated audit (optional but recommended)

The unauthenticated checks (UPnP port forwards, admin surface) work without credentials. For deeper inspection — firmware version, WAN config, connected client list — copy the example config and fill it in:

```bash
cp router_config.example.json router_config.json
chmod 600 router_config.json   # important
nano router_config.json
```

The example targets ASUS — for other routers, send your make/model and I'll generate the right `login_url` / `pages` / `selectors`.

## Cost

| Scenario | OpenAI cost (approx) |
|----------|---------------------|
| `--quick --no-llm` | $0 |
| `--quick` | $0.30-0.80 |
| Full audit | $1-4 |

Costs are GPT-5.5 high-reasoning rates. Set a $10/mo cap in your OpenAI billing dashboard if you schedule this weekly. The NVD CVE lookups are free but rate-limited (6 sec/query without an API key — slow but reliable).

## Sample output structure

The GPT-5.5 report has these sections:

1. **Executive Summary** — one paragraph, the single biggest risk
2. **Three Most Realistic Attack Paths** — full kill chains with steps, the defense that breaks each one, and effort to fix
3. **Per-Device Threat Model** — every device with its specific playbook
4. **Critical CVEs** — real vulns with CVSS ≥ 7 and exploit availability
5. **Router & Perimeter** — UPnP exposure, WAN-facing services
6. **Patches in Priority Order** — ranked by risk reduction per minute of work
7. **False Positives to Ignore** — nmap noise

## What this does NOT do

- **No active exploitation.** Nothing in this tool actually attempts to log in, exploit, or change anything. It enumerates surface and looks up known vulns.
- **No external scanning of other networks.** Only your LAN and your own public IP.
- **No decryption of browser passwords.** We report that stores exist; we don't crack DPAPI even on your own machine.
- **No router config changes.** Even with `router_config.json`, the script only reads admin pages.

## Files

```
security-auditor/
├── security_audit.py            # main orchestrator
├── windows_audit.ps1            # PowerShell collector for Windows host
├── router_config.example.json   # template for authenticated router audit
├── modules/
│   ├── fingerprint.py           # device identification + attack profiles
│   ├── cve.py                   # NVD + ExploitDB lookups
│   ├── router.py                # UPnP enumeration, admin surface, auth scrape
│   ├── wireless.py              # netsh wlan parsing
│   ├── credentials.py           # email enumeration, HIBP, store locations
│   ├── external.py              # public IP, Shodan InternetDB
│   └── attack_paths.py          # GPT-5.5 kill-chain synthesizer
└── README.md
```

## Caveats

- First run will surprise you. Most home networks have 10-25 devices and a few you forgot about.
- nmap vuln scripts produce false positives. The LLM is prompted to flag them; spot-check before acting.
- UPnP enumeration only works if your router has UPnP enabled. If it's off (good!) you'll see 0 mappings.
