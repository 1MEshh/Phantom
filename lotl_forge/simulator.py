"""SIEM Log & Telemetry Audit Recorder.

Provides strictly non-destructive version/help process probes (shell=False,
timeout=5s) or synthetic Sysmon / Linux Auditd JSON test events so Blue Team
detection engineers can verify SIEM log ingestion and correlation rules
without executing dangerous commands.
"""

from __future__ import annotations

import datetime
import hashlib
import hmac
import json
import os
import shutil
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from lotl_forge.catalog import BinaryEntry, filter_by_technique, get_catalog
from lotl_forge.scanner import compute_file_sha256, detect_host_os


@dataclass
class TelemetryRecord:
    """Single process probe or synthetic telemetry verification event."""

    binary_name: str
    target_os: str
    mitre_techniques: List[str]
    execution_mode: str  # "live-version-probe" | "dry-run-synthetic"
    resolved_path: Optional[str]
    binary_sha256: Optional[str]
    argv: List[str]
    pid: Optional[int]
    ppid: int
    start_time_utc: str
    end_time_utc: str
    exit_code: Optional[int]
    expected_log_source: str
    synthetic_siem_event: Dict[str, Any]
    record_hmac_sha256: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def _build_synthetic_siem_event(
    entry: BinaryEntry,
    resolved_path: str,
    argv: Sequence[str],
    sha256_hex: str,
    pid: int,
    ppid: int,
    timestamp_utc: str,
) -> Dict[str, Any]:
    """Construct a structured Sysmon EventID 1 or Linux auditd EXECVE JSON payload for SIEM ingestion testing."""
    cmd_line = " ".join(argv)
    if entry.target_os == "windows":
        return {
            "EventChannel": "Microsoft-Windows-Sysmon/Operational",
            "EventID": 1,
            "UtcTime": timestamp_utc,
            "ProcessId": pid,
            "ParentProcessId": ppid,
            "Image": resolved_path,
            "CommandLine": cmd_line,
            "Hashes": f"SHA256={sha256_hex.upper()}",
            "RuleName": f"technique_id={','.join(entry.mitre_techniques)},binary={entry.name}",
            "TelemetryVerificationOnly": True,
        }
    return {
        "log_source": "linux-auditd",
        "record_type": "SYSCALL_EXECVE",
        "timestamp_utc": timestamp_utc,
        "syscall": "execve",
        "pid": pid,
        "ppid": ppid,
        "exe": resolved_path,
        "argc": len(argv),
        "argv": list(argv),
        "sha256": sha256_hex,
        "mitre_techniques": list(entry.mitre_techniques),
        "telemetry_verification_only": True,
    }


def _sign_record(payload: Dict[str, Any], secret_key: bytes) -> str:
    """Compute a constant-time verifiable HMAC-SHA256 signature over the telemetry record."""
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(secret_key, canonical, hashlib.sha256).hexdigest()


def verify_record_signature(record: TelemetryRecord, secret_key: bytes) -> bool:
    """Verify telemetry record integrity using constant-time hmac.compare_digest."""
    data = record.to_dict()
    provided_sig = str(data.pop("record_hmac_sha256", ""))
    expected_sig = _sign_record(data, secret_key)
    return hmac.compare_digest(provided_sig.encode("ascii"), expected_sig.encode("ascii"))


def run_telemetry_verification(
    confirm_authorized_scope: bool,
    requested_os: str = "auto",
    technique_filter: Optional[str] = None,
    dry_run: bool = False,
    hmac_key: Optional[bytes] = None,
) -> List[TelemetryRecord]:
    """Run safe version/help probes or emit synthetic SIEM events for catalog entries."""
    if not confirm_authorized_scope:
        raise PermissionError(
            "Telemetry verification requires explicit authorization flag (--confirm-authorized-scope)."
        )

    target_os = detect_host_os(requested_os)
    if technique_filter:
        entries = filter_by_technique(technique_filter, target_os=target_os)
        if not entries:
            # Also search cross-OS if explicit technique requested in dry-run mode
            entries = filter_by_technique(technique_filter, target_os=None)
    else:
        entries = get_catalog(target_os)

    signing_key = hmac_key or os.environ.get(
        "LOTL_FORGE_HMAC_KEY", "lotl-forge-default-audit-integrity-key"
    ).encode("utf-8")

    records: List[TelemetryRecord] = []
    ppid = os.getpid()

    for entry in entries:
        resolved = shutil.which(entry.name)
        is_cross_os = entry.target_os != detect_host_os("auto")
        effective_dry_run = dry_run or is_cross_os or (resolved is None)

        if resolved:
            resolved_path_str = str(Path(resolved))
            sha256_hex = compute_file_sha256(Path(resolved)) or ("0" * 64)
            argv = [resolved_path_str] + list(entry.safe_probe_args[1:])
        else:
            if entry.target_os == "windows":
                resolved_path_str = f"C:\\Windows\\System32\\{entry.name}"
            else:
                resolved_path_str = f"/usr/bin/{entry.name}"
            sha256_hex = hashlib.sha256(entry.name.encode("utf-8")).hexdigest()
            argv = [resolved_path_str] + list(entry.safe_probe_args[1:])

        start_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()

        if effective_dry_run:
            end_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
            pid: Optional[int] = None
            exit_code: Optional[int] = 0
            mode_label = "dry-run-synthetic"
        else:
            try:
                proc = subprocess.Popen(
                    argv,
                    shell=False,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    stdin=subprocess.DEVNULL,
                )
                pid = proc.pid
                try:
                    exit_code = proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
                    exit_code = -1
            except OSError:
                pid = None
                exit_code = -1
            end_utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
            mode_label = "live-version-probe"

        synthetic_event = _build_synthetic_siem_event(
            entry=entry,
            resolved_path=resolved_path_str,
            argv=argv,
            sha256_hex=sha256_hex,
            pid=pid or 0,
            ppid=ppid,
            timestamp_utc=start_utc,
        )

        unsigned_dict: Dict[str, Any] = {
            "binary_name": entry.name,
            "target_os": entry.target_os,
            "mitre_techniques": list(entry.mitre_techniques),
            "execution_mode": mode_label,
            "resolved_path": resolved if resolved else None,
            "binary_sha256": sha256_hex,
            "argv": argv,
            "pid": pid,
            "ppid": ppid,
            "start_time_utc": start_utc,
            "end_time_utc": end_utc,
            "exit_code": exit_code,
            "expected_log_source": str(entry.expected_telemetry.get("source", "siem")),
            "synthetic_siem_event": synthetic_event,
        }
        signature = _sign_record(unsigned_dict, signing_key)

        records.append(
            TelemetryRecord(
                binary_name=entry.name,
                target_os=entry.target_os,
                mitre_techniques=list(entry.mitre_techniques),
                execution_mode=mode_label,
                resolved_path=resolved if resolved else None,
                binary_sha256=sha256_hex,
                argv=argv,
                pid=pid,
                ppid=ppid,
                start_time_utc=start_utc,
                end_time_utc=end_utc,
                exit_code=exit_code,
                expected_log_source=str(entry.expected_telemetry.get("source", "siem")),
                synthetic_siem_event=synthetic_event,
                record_hmac_sha256=signature,
            )
        )

    return records
