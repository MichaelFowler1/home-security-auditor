#!/usr/bin/env python3
"""
Generate docs/hero.png - the README image.

An illustrative view of what the auditor does: a LAN map with each device
colored by the *pivot value* the tool actually assigns it (pulled live from
modules/fingerprint.py's ATTACK_PROFILES), plus a sample kill chain and the
report's section list.

NOTE: this renders a representative sample topology - it does NOT scan any
network. The real tool is read-only and only ever scans your own LAN.

Run:  python make_hero.py     (needs matplotlib)
"""
import math
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch

from modules.fingerprint import ATTACK_PROFILES

BG, PANEL, INK, DIM = "#070b12", "#0b1220", "#d7e2f0", "#7d8ea6"
# pivot value -> color (keys match the leading word in ATTACK_PROFILES[*]["pivot_value"])
TIER = {"critical": "#ff3b3b", "very high": "#ff7a2f", "high": "#ffb020",
        "medium": "#4db6ff", "low": "#5fd08a", "unknown": "#8899aa"}


def tier_of(device_class):
    pv = ATTACK_PROFILES.get(device_class, ATTACK_PROFILES["unknown"])["pivot_value"]
    for key in ("critical", "very high", "high", "medium", "low"):
        if pv.startswith(key):
            return key
    return "unknown"


# a representative home LAN (the kind the tool finds on a first run)
DEVICES = [
    ("ip_camera", "Reolink cam", ".14"),
    ("nas", "Synology NAS", ".20"),
    ("printer", "HP OfficeJet", ".31"),
    ("smart_tv", "Roku TV", ".42"),
    ("smart_speaker", "Echo Dot", ".55"),
    ("doorbell", "Ring doorbell", ".61"),
    ("game_console", "PlayStation", ".77"),
    ("thermostat", "Nest", ".88"),
]

plt.rcParams.update({"font.family": "DejaVu Sans", "text.color": INK})
fig = plt.figure(figsize=(13, 7.2), facecolor=BG)
fig.text(0.05, 0.945, "HOME NETWORK  ETHICAL-HACKER AUDITOR",
         fontsize=17, fontweight="bold")
fig.text(0.05, 0.898, "nmap  →  device fingerprint + attack profile  →  CVE/NVD + ExploitDB  →  "
                      "router / wireless / host  →  GPT kill-chain report",
         fontsize=10, color=DIM)
fig.text(0.95, 0.945, "READ-ONLY", ha="right", fontsize=12,
         fontweight="bold", color="#5fd08a")
fig.text(0.95, 0.900, "enumerate & look up known vulns · never exploits",
         ha="right", fontsize=9, color=DIM)

# ---------- left: LAN map ----------
axm = fig.add_axes([0.03, 0.06, 0.57, 0.78])
axm.set_xlim(-2.15, 2.15); axm.set_ylim(-1.55, 1.45)
axm.axis("off")

# router hub
axm.scatter([0], [0], s=1700, marker="s", facecolor=PANEL,
            edgecolor=TIER["critical"], linewidth=2.5, zorder=5)
axm.text(0, 0, "ROUTER\nMITM +\nUPnP", ha="center", va="center",
         fontsize=8.5, fontweight="bold", color=INK, zorder=6)

n = len(DEVICES)
for k, (cls, name, ip) in enumerate(DEVICES):
    ang = math.pi / 2 - 2 * math.pi * k / n
    x, y = 1.02 * math.cos(ang), 1.02 * math.sin(ang)
    tier = tier_of(cls)
    col = TIER[tier]
    axm.plot([0, x * 0.62], [0, y * 0.62], color=col, alpha=0.35, linewidth=1.3, zorder=1)
    axm.scatter([x * 0.72], [y * 0.72], s=540, facecolor=PANEL,
                edgecolor=col, linewidth=2.2, zorder=4)
    # port count from the real profile
    nports = len(ATTACK_PROFILES[cls]["common_ports"])
    axm.text(x * 0.72, y * 0.72, cls.split("_")[0].upper()[:6],
             ha="center", va="center", fontsize=6.6, fontweight="bold", color=col, zorder=5)
    label = f"{name}  10.0.0{ip}\n{tier} pivot · {nports} ports"
    ha = "left" if x >= 0 else "right"
    lx = x * 1.10 + (0.16 if x >= 0 else -0.16)
    ly = y * 1.10
    if abs(x) < 0.2:            # top/bottom nodes: lift label clear of the marker
        ly = y * 1.10 + (0.18 if y > 0 else -0.18)
    axm.text(lx, ly, label, ha=ha, va="center", fontsize=7.4, color=INK, zorder=5)

# legend
for i, (t, c) in enumerate([("critical", TIER["critical"]), ("very high", TIER["very high"]),
                            ("high", TIER["high"]), ("medium", TIER["medium"]), ("low", TIER["low"])]):
    axm.scatter([-2.1 + i * 0.62], [-1.5], s=80, color=c)
    axm.text(-2.03 + i * 0.62, -1.5, t, fontsize=7.2, va="center", color=DIM)

# ---------- right: kill chain + sections ----------
axk = fig.add_axes([0.615, 0.44, 0.365, 0.40], facecolor=PANEL)
axk.axis("off")
for s in axk.spines.values():
    s.set_visible(False)
axk.add_patch(FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0.0,rounding_size=0.02",
              transform=axk.transAxes, facecolor=PANEL, edgecolor="#ff7a2f", linewidth=1.5))
axk.text(0.05, 0.90, "SAMPLE KILL CHAIN  #1", fontsize=11, fontweight="bold",
         color="#ff7a2f", transform=axk.transAxes)
steps = [
    "1. Printer SNMP 'public' → leak LDAP creds",
    "2. Reuse creds on Synology NAS admin",
    "3. NAS CVE (RCE, runs as root) → foothold",
    "4. Pivot to router via UPnP → DNS hijack",
]
for i, s in enumerate(steps):
    axk.text(0.05, 0.72 - i * 0.15, s, fontsize=9, color=INK, transform=axk.transAxes)
axk.text(0.05, 0.08, "break it here: SNMP off + unique NAS creds",
         fontsize=8.2, style="italic", color="#5fd08a", transform=axk.transAxes)

axs = fig.add_axes([0.615, 0.05, 0.365, 0.34], facecolor=PANEL)
axs.axis("off")
axs.add_patch(FancyBboxPatch((0, 0), 1, 1, boxstyle="round,pad=0.0,rounding_size=0.02",
              transform=axs.transAxes, facecolor=PANEL, edgecolor="#1b2740", linewidth=1.5))
axs.text(0.05, 0.88, "REPORT SECTIONS", fontsize=11, fontweight="bold",
         color=INK, transform=axs.transAxes)
sections = ["Executive summary — the single biggest risk",
            "3 most realistic attack paths",
            "Per-device threat model + playbook",
            "Critical CVEs (CVSS ≥ 7, exploit available)",
            "Patches ranked by risk-reduction / minute"]
for i, s in enumerate(sections):
    axs.text(0.05, 0.70 - i * 0.145, "• " + s, fontsize=8.6, color=INK, transform=axs.transAxes)

fig.text(0.05, 0.012, "Illustrative sample — pivot tiers pulled from modules/fingerprint.py. "
                      "The tool scans only your own LAN and never exploits.",
         fontsize=8, color=DIM)

os.makedirs("docs", exist_ok=True)
fig.savefig("docs/hero.png", dpi=140, facecolor=BG)
print("[+] wrote docs/hero.png")
for cls, name, ip in DEVICES:
    print(f"    {name:16} {cls:14} pivot={tier_of(cls)}")
