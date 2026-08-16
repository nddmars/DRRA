"""
DRRA-076 — Raw OTRF Security-Datasets ingestion and IoB feature extraction.

Parses the OTRF/Mordor event schema (one JSON object per line: Windows Security
and Sysmon events with fields such as ``EventID``, ``Channel``, ``Hostname``,
``TimeCreated``, ``Image``/``ProcessName``, ``CommandLine``, ``TargetFilename``,
``LogonType``, ``TargetImage``) and converts it into the four Indicators of
Behavior the VIGIL model scores:

    file_rename_rate          Sysmon file create/delete/modify events per second
    lateral_movement_score    network logons / SMB-RDP-WinRM connections per second
    privilege_escalation      LSASS access, special-privilege, token events per second
    shadow_copy_deletion_rate vssadmin/wmic/wbadmin/bcdedit recovery-inhibition events per second

This replaces the synthetic scenario generator with genuine adversary telemetry:
the model scores IoB windows derived from real recorded attacks. Each event's
contribution to a feature is documented inline so the mapping is auditable
(DRRA-019 explainability, DRRA-075 traceability).

Feature values are counts per second within a fixed time window per host, so a
burst of malicious activity produces an elevated vector the same way the live
Rust watcher / SIEM pipeline would.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Iterable, List, Optional, Tuple

# Event-ID sets per IoB family (documented mapping) ---------------------------
FILE_EVENTS = {11, 23, 26, 2}          # Sysmon: FileCreate, FileDelete(Detected), FileCreateTime
NETWORK_LOGON_EVENTS = {4624, 4648}    # Security: network/explicit logon
SYSMON_NETWORK = {3}                   # Sysmon: network connection
LATERAL_PORTS = {445, 3389, 5985, 5986, 135, 139}
PRIVESC_EVENTS = {4672, 4673, 4674, 4703}  # special privileges / token / sensitive-privilege
HANDLE_EVENTS = {4656, 4663, 4658}     # object handle (checked against lsass target)
SYSMON_PROCESS_ACCESS = {10}           # Sysmon: ProcessAccess (checked against lsass target)
PROCESS_CREATE_EVENTS = {1, 4688}      # Sysmon ProcessCreate / Security process creation

SHADOW_DELETE_RE = re.compile(
    r"(vssadmin.*delete\s+shadows|wmic.*shadowcopy.*delete|wbadmin\s+delete|"
    r"bcdedit.*(recoveryenabled\s+no|bootstatuspolicy)|Remove-Item.*shadow|"
    r"Get-WmiObject\s+Win32_Shadowcopy.*Delete)",
    re.IGNORECASE,
)

_TS_FORMATS = ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S.%fZ",
               "%Y-%m-%d %H:%M:%S")


@dataclass
class WindowFeature:
    host: str
    t_offset: float              # seconds since dataset start
    file_rename_rate: float
    lateral_movement_score: float
    privilege_escalation: float
    shadow_copy_deletion_rate: float

    def as_iob(self):
        """Return a vigil.ml_model.IoBVector (imported lazily to avoid a cycle)."""
        from vigil.ml_model import IoBVector

        return IoBVector(
            file_rename_rate=self.file_rename_rate,
            lateral_movement_score=self.lateral_movement_score,
            privilege_escalation=self.privilege_escalation,
            shadow_copy_deletion_rate=self.shadow_copy_deletion_rate,
        )


@dataclass
class IngestStats:
    total_events: int = 0
    parsed_events: int = 0
    malformed_lines: int = 0          # JSON lines that failed to parse (not silent)
    hosts: set = field(default_factory=set)
    signal_events: Dict[str, int] = field(default_factory=lambda: {
        "file": 0, "lateral": 0, "privesc": 0, "shadow": 0})

    @property
    def total_signals(self) -> int:
        return sum(self.signal_events.values())


def _parse_ts(value: str) -> Optional[float]:
    if not value:
        return None
    v = str(value).strip()
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(v, fmt).timestamp()
        except (ValueError, TypeError):
            continue
    return None


def parse_events(path: str, stats: Optional["IngestStats"] = None) -> Iterable[dict]:
    """Yield event dicts from an OTRF JSON-lines dataset (or a plain JSON list).

    Malformed JSON lines are counted on ``stats.malformed_lines`` (if provided)
    instead of being silently discarded, so ingestion failures are observable."""
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        first = fh.read(1)
        fh.seek(0)
        if first == "[":                      # a JSON array
            for e in json.load(fh):
                yield e
            return
        for line in fh:                       # JSON lines
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                if stats is not None:
                    stats.malformed_lines += 1
                continue


def _event_id(e: dict) -> Optional[int]:
    v = e.get("EventID", e.get("event_id"))
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _targets_lsass(e: dict) -> bool:
    for k in ("TargetImage", "ObjectName", "TargetObject"):
        val = str(e.get(k, "")).lower()
        if "lsass" in val:
            return True
    return False


def classify_event(e: dict, stats: Optional[IngestStats] = None) -> Optional[str]:
    """Return which IoB family an event contributes to, or None."""
    eid = _event_id(e)
    if eid is None:
        return None
    channel = str(e.get("Channel", ""))
    is_sysmon = "Sysmon" in channel

    # Shadow-copy / recovery inhibition (highest specificity first)
    if eid in PROCESS_CREATE_EVENTS:
        cmd = str(e.get("CommandLine", e.get("ProcessName", e.get("Image", ""))))
        if SHADOW_DELETE_RE.search(cmd):
            return "shadow"
    # File activity
    if is_sysmon and eid in FILE_EVENTS:
        return "file"
    # Lateral movement
    if eid in NETWORK_LOGON_EVENTS:
        if eid == 4624 and str(e.get("LogonType", "")) not in ("3", "10"):
            return None  # only network / remote-interactive logons count
        return "lateral"
    if is_sysmon and eid in SYSMON_NETWORK:
        try:
            port = int(e.get("DestinationPort", -1))
        except (TypeError, ValueError):
            port = -1
        if port in LATERAL_PORTS:
            return "lateral"
    # Privilege escalation / credential access
    if eid in PRIVESC_EVENTS:
        return "privesc"
    if is_sysmon and eid in SYSMON_PROCESS_ACCESS and _targets_lsass(e):
        return "privesc"
    if eid in HANDLE_EVENTS and _targets_lsass(e):
        return "privesc"
    return None


def extract_windows(
    path: str, window_seconds: float = 10.0, host: Optional[str] = None
) -> Tuple[List[WindowFeature], IngestStats]:
    """
    Ingest a dataset and return per-host, per-window IoB feature vectors plus
    ingestion statistics. If ``host`` is given, only that host is included.
    """
    stats = IngestStats()
    events: List[Tuple[float, str, str]] = []   # (ts, host, family)
    t_min: Optional[float] = None

    for e in parse_events(path, stats):
        stats.total_events += 1
        ts = _parse_ts(e.get("TimeCreated", e.get("@timestamp", "")))
        if ts is None:
            continue
        hname = str(e.get("Hostname", e.get("Computer", "unknown")))
        if host and hname != host:
            continue
        family = classify_event(e, stats)
        stats.parsed_events += 1
        stats.hosts.add(hname)
        t_min = ts if t_min is None else min(t_min, ts)
        if family:
            stats.signal_events[family] += 1
            events.append((ts, hname, family))

    if t_min is None or not events:
        return [], stats

    # Bucket signal events into per-host time windows.
    buckets: Dict[Tuple[str, int], Dict[str, int]] = {}
    for ts, hname, family in events:
        widx = int((ts - t_min) // window_seconds)
        key = (hname, widx)
        buckets.setdefault(key, {"file": 0, "lateral": 0, "privesc": 0, "shadow": 0})
        buckets[key][family] += 1

    features: List[WindowFeature] = []
    for (hname, widx), counts in sorted(buckets.items(), key=lambda kv: (kv[0][0], kv[0][1])):
        features.append(WindowFeature(
            host=hname,
            t_offset=widx * window_seconds,
            file_rename_rate=counts["file"] / window_seconds,
            lateral_movement_score=counts["lateral"] / window_seconds,
            privilege_escalation=counts["privesc"] / window_seconds,
            shadow_copy_deletion_rate=counts["shadow"] / window_seconds,
        ))
    return features, stats
