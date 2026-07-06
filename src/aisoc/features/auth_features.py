"""Authentication-behavior features (Windows logon events). Phase 2.5 — after process features.

Planned, per (user, window):
- login_count / failed_count / failed_ratio
- hour_of_day deviation from this user's historical login-hour distribution
- new_source_ip (first-seen for this user)
- distinct_hosts touched (lateral-movement signal, T1021)
"""

import pandas as pd


def extract(auth_events: pd.DataFrame) -> pd.DataFrame:
    raise NotImplementedError
