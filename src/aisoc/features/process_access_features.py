"""Process-access behavior features from Sysmon EID 10 (ProcessAccess).

Sysmon EID 10 fires when one process opens a handle to another process. It is the
primary telemetry for two of the highest-value attacker tactics — the ones the
process/network/DNS families are blind to:

  - Credential Access (T1003.001): a process opens **lsass.exe** with memory-read
    rights to scrape credentials from its memory. This is the canonical mimikatz /
    comsvcs MiniDump behavior — it shows up here, not in process creation.
  - Defense Evasion / Privilege Escalation via Process Injection (T1055): a process
    opens a target with VM_WRITE / CREATE_THREAD rights to run code inside it.

Sysmon records the granted rights as a hex mask (GrantedAccess). The specific bits
are what separate a benign query from credential theft or injection.

Per (host, window):
- proc_access_count        total ProcessAccess events (volume baseline)
- lsass_access_count       accesses targeting lsass.exe (credential dumping)
- sensitive_access_count   accesses targeting any sensitive system process
- high_access_count        accesses granting memory read/write/inject rights
- distinct_access_targets  distinct target images accessed (injection/recon spray)
"""

import pandas as pd

from aisoc.features.windows import assign_windows

COL_HOST = "agent.name"
COL_SOURCE = "data.win.eventdata.sourceImage"
COL_TARGET = "data.win.eventdata.targetImage"
COL_GRANTED = "data.win.eventdata.grantedAccess"

# Processes whose memory is a high-value target for theft or injection.
SENSITIVE_TARGETS = {
    "lsass.exe",     # credentials in memory (mimikatz / comsvcs)
    "winlogon.exe",  # session + credential material
    "csrss.exe",
    "services.exe",
    "lsm.exe",
}

# GrantedAccess right-bits that matter (Windows PROCESS_* constants). A handle
# that includes any of these — especially on a sensitive target — is the
# credential-dump / injection signature rather than a benign status query.
_VM_READ = 0x0010        # read another process's memory (mimikatz reads lsass)
_VM_WRITE = 0x0020       # write another process's memory (injection)
_VM_OPERATION = 0x0008   # change memory protection (injection)
_CREATE_THREAD = 0x0002  # start a thread in another process (injection)
_DANGEROUS_BITS = _VM_READ | _VM_WRITE | _VM_OPERATION | _CREATE_THREAD

FEATURE_COLUMNS = [
    "proc_access_count",
    "lsass_access_count",
    "sensitive_access_count",
    "high_access_count",
    "distinct_access_targets",
]


def is_dangerous_access(granted: str) -> bool:
    """True if a GrantedAccess mask includes memory read/write/inject rights.

    GrantedAccess is a hex string like ``0x1010`` or ``0x1fffff``. mimikatz's
    classic lsass open is 0x1010 (VM_READ | QUERY_LIMITED_INFORMATION); injection
    uses VM_WRITE / CREATE_THREAD; full access (0x1F0FFF / 0x1FFFFF) includes all.
    """
    s = str(granted).strip()
    if not s:
        return False
    try:
        mask = int(s, 16) if s.lower().startswith("0x") else int(s)
    except (ValueError, TypeError):
        return False
    return bool(mask & _DANGEROUS_BITS)


def _image_name(image: str) -> str:
    return str(image).lower().split("\\")[-1]


def extract(access_events: pd.DataFrame) -> pd.DataFrame:
    """Sysmon EID-10 events -> one feature row per (host, window)."""
    if access_events is None or access_events.empty:
        return pd.DataFrame(columns=["host", "window_start"] + FEATURE_COLUMNS)

    ev = assign_windows(access_events)
    for col in (COL_SOURCE, COL_TARGET, COL_GRANTED):
        if col not in ev:
            ev[col] = ""
        ev[col] = ev[col].fillna("").astype(str)

    ev["target_name"] = ev[COL_TARGET].map(_image_name)
    ev["is_lsass"] = ev["target_name"].eq("lsass.exe")
    ev["is_sensitive"] = ev["target_name"].isin(SENSITIVE_TARGETS)
    ev["is_dangerous"] = ev[COL_GRANTED].map(is_dangerous_access)

    g = ev.groupby([COL_HOST, "window_start"])
    out = pd.DataFrame(
        {
            "proc_access_count": g.size(),
            "lsass_access_count": g["is_lsass"].sum(),
            "sensitive_access_count": g["is_sensitive"].sum(),
            "high_access_count": g["is_dangerous"].sum(),
            "distinct_access_targets": g["target_name"].nunique(),
        }
    ).reset_index()
    return out.rename(columns={COL_HOST: "host"})
