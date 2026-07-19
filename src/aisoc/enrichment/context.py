"""Cheap, offline enrichment context that helps triage separate benign noise from
real threats without a human doing the lookups by hand.

For the observable names and IPs on an alert it flags three things:
  * recognized legitimate tools  -> benign indicator (supports LOWERING severity)
  * living-off-the-land binaries -> escalation indicator (dual-use, verify usage)
  * threat-intel IP hits         -> escalation indicator (known-bad infrastructure)

Everything here is static or read from a local file, so it runs with no network
and no paid API — the constraint the whole project is under. The TI blocklist is
refreshed out-of-band by scripts/update_threat_intel.py from the free abuse.ch
feed; when the file is absent, TI lookups are simply a no-op.
"""

from collections.abc import Iterable
from pathlib import Path

# Recognizable legitimate tools: basename (lowercase) -> what it is. A match is a
# benign signal — these commonly trip anomaly/rule detections while doing exactly
# what they are designed to do (inject, drop files, load unsigned modules).
KNOWN_LEGIT_TOOLS: dict[str, str] = {
    "windhawk.exe": "Windhawk (Windows customization tool; injects into apps by design)",
    "robloxplayerbeta.exe": "Roblox game client",
    "chrome.exe": "Google Chrome",
    "msedge.exe": "Microsoft Edge",
    "firefox.exe": "Mozilla Firefox",
    "teams.exe": "Microsoft Teams",
    "code.exe": "Visual Studio Code",
    "discord.exe": "Discord",
    "steam.exe": "Steam",
    "onedrive.exe": "OneDrive sync client",
    "slack.exe": "Slack",
    "spotify.exe": "Spotify",
    "obs64.exe": "OBS Studio",
    "notepad++.exe": "Notepad++",
    "everything.exe": "Everything search",
}

# Common living-off-the-land binaries (curated subset of lolbas-project.github.io).
# Legitimate signed Windows tools that attackers frequently abuse. Presence is not
# an alarm on its own — it means look at HOW the binary was used (child process,
# command line, network) before concluding anything.
LOLBAS: frozenset[str] = frozenset({
    "certutil.exe", "regsvr32.exe", "rundll32.exe", "mshta.exe", "wmic.exe",
    "bitsadmin.exe", "installutil.exe", "regasm.exe", "regsvcs.exe", "msbuild.exe",
    "cscript.exe", "wscript.exe", "cmstp.exe", "control.exe", "forfiles.exe",
    "pcalua.exe", "msdt.exe", "hh.exe", "ieexec.exe", "presentationhost.exe",
    "odbcconf.exe", "schtasks.exe", "sc.exe", "reg.exe", "vssadmin.exe",
    "wbadmin.exe", "esentutl.exe", "makecab.exe", "expand.exe", "extrac32.exe",
    "mavinject.exe", "msxsl.exe", "print.exe", "replace.exe", "xwizard.exe",
})

DEFAULT_TI_PATH = Path("data/threat_intel/ip_blocklist.txt")


def _basename(name: str) -> str:
    """Lowercase file basename from a Windows or POSIX path (or a bare name)."""
    return name.replace("\\", "/").rsplit("/", 1)[-1].strip().lower()


def known_tool_hits(names: Iterable[str]) -> dict[str, str]:
    """Map of {matched basename: description} for recognized legitimate tools."""
    out: dict[str, str] = {}
    for n in names:
        base = _basename(n)
        if base in KNOWN_LEGIT_TOOLS and base not in out:
            out[base] = KNOWN_LEGIT_TOOLS[base]
    return out


def lolbas_hits(names: Iterable[str]) -> list[str]:
    """Sorted, de-duplicated list of living-off-the-land binaries among ``names``."""
    return sorted({_basename(n) for n in names if _basename(n) in LOLBAS})


class IpReputation:
    """Membership check against a local IP blocklist (abuse.ch format: one IP per
    line, ``#`` comments ignored). No network here — the file is refreshed by
    scripts/update_threat_intel.py. A missing file yields an empty, no-op set.
    """

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or DEFAULT_TI_PATH
        self.blocklist: set[str] = set()
        if self.path.exists():
            for line in self.path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    self.blocklist.add(line.split(",")[0].strip())

    def hits(self, ips: Iterable[str]) -> list[str]:
        return sorted({ip.strip() for ip in ips if ip.strip() in self.blocklist})


def build_context(
    names: Iterable[str],
    ips: Iterable[str] = (),
    ti: IpReputation | None = None,
) -> dict:
    """Collect benign vs. escalation indicators for one alert's observables.

    Returns {"benign_indicators": [...], "escalation_indicators": [...]} — each a
    list of short human-readable strings the copilot can weigh. Empty lists are a
    valid, common result (nothing recognized either way).
    """
    names = list(names)
    benign: list[str] = []
    escalate: list[str] = []

    for base, desc in known_tool_hits(names).items():
        benign.append(f"{base} is a recognized legitimate tool: {desc}")

    for lol in lolbas_hits(names):
        escalate.append(
            f"{lol} is a living-off-the-land binary (legitimate but abuse-prone) — "
            "check its command line and child processes"
        )

    if ips:
        ti = ti or IpReputation()
        for ip in ti.hits(ips):
            escalate.append(f"{ip} appears on a threat-intel blocklist (known-bad infrastructure)")

    return {"benign_indicators": benign, "escalation_indicators": escalate}


def format_context(ctx: dict) -> str:
    """Render build_context() output as a short grounding block for the LLM."""
    lines: list[str] = []
    for b in ctx.get("benign_indicators", []):
        lines.append(f"- BENIGN: {b}")
    for e in ctx.get("escalation_indicators", []):
        lines.append(f"- ATTENTION: {e}")
    return "\n".join(lines) if lines else "- No recognized tools, LOLBins, or TI hits among the observables."
