"""Read-only endpoint binary posture and PATH hygiene scanner.

Audits either the live local filesystem or an offline JSON host manifest for:
- World-writable or user-writable directories in the system PATH.
- Unexpected SUID/SGID mode bits (stat.S_ISUID, stat.S_ISGID) or elevated Linux
  file capabilities on dual-use administrative utilities.
- Unblocked legacy utilities on Windows (System32/SysWOW64) and AppLocker/WDAC
  policy enforcement state.
- Computes both a Host Hardening Score (0-100, higher is better) and its inverse
  Host Exposure Score (0-100) along with prioritized remediation controls.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import platform
import shutil
import stat
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from lotl_forge.catalog import BinaryEntry, get_catalog


@dataclass
class BinaryFinding:
    """Audit result for a single catalog binary on the target host."""

    name: str
    target_os: str
    present: bool
    resolved_path: Optional[str]
    sha256: Optional[str]
    mode_octal: Optional[str]
    suid_bit: bool
    sgid_bit: bool
    world_writable_binary: bool
    file_capabilities: List[str]
    policy_blocked: bool
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    risk_score: int
    mitre_techniques: List[str]
    hardening_controls: List[str]
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanReport:
    """Aggregate posture report for a scanned endpoint or manifest."""

    hostname: str
    scanned_os: str
    scan_mode: str  # "live" | "manifest"
    timestamp_utc: str
    hardening_score: int
    exposure_score: int
    risk_rating: str
    writable_path_dirs: List[str]
    policy_enforcement: Dict[str, bool]
    total_catalog_checked: int
    present_count: int
    high_risk_count: int
    findings: List[BinaryFinding]
    remediation_plan: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "scanned_os": self.scanned_os,
            "scan_mode": self.scan_mode,
            "timestamp_utc": self.timestamp_utc,
            "hardening_score": self.hardening_score,
            "exposure_score": self.exposure_score,
            "risk_rating": self.risk_rating,
            "writable_path_dirs": list(self.writable_path_dirs),
            "policy_enforcement": dict(self.policy_enforcement),
            "total_catalog_checked": self.total_catalog_checked,
            "present_count": self.present_count,
            "high_risk_count": self.high_risk_count,
            "findings": [f.to_dict() for f in self.findings],
            "remediation_plan": list(self.remediation_plan),
        }


def detect_host_os(requested_os: str = "auto") -> str:
    """Resolve 'auto' to 'windows' or 'linux' based on the running platform."""
    req = (requested_os or "auto").lower().strip()
    if req in ("linux", "windows"):
        return req
    sys_name = platform.system().lower()
    if "windows" in sys_name or os.name == "nt":
        return "windows"
    return "linux"


def compute_file_sha256(file_path: Path, max_bytes: int = 50 * 1024 * 1024) -> Optional[str]:
    """Compute SHA-256 digest of a binary safely without loading the whole file in memory."""
    try:
        if not file_path.is_file():
            return None
        size = file_path.stat().st_size
        if size > max_bytes:
            return None
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            while True:
                chunk = handle.read(65536)
                if not chunk:
                    break
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _inspect_linux_capabilities(file_path: Path) -> List[str]:
    """Check security.capability extended attribute on Linux if supported by os.getxattr."""
    getxattr = getattr(os, "getxattr", None)
    if getxattr is None:
        return []
    try:
        raw = getxattr(str(file_path), "security.capability")
        if raw:
            return [f"security.capability(len={len(raw)})"]
    except OSError:
        pass
    return []


def _audit_writable_path_dirs(path_entries: Sequence[str]) -> List[str]:
    """Identify directories in PATH that are world-writable without sticky bit or risky."""
    writable: List[str] = []
    seen = set()
    for raw_dir in path_entries:
        cleaned = raw_dir.strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        if cleaned in (".", "./", ".\\"):
            writable.append(cleaned)
            continue
        try:
            st = os.stat(cleaned)
            mode = st.st_mode
            is_world_writable = bool(mode & stat.S_IWOTH)
            has_sticky = bool(mode & stat.S_ISVTX)
            if is_world_writable and not has_sticky:
                writable.append(cleaned)
        except OSError:
            continue
    return writable


def _classify_finding(
    entry: BinaryEntry,
    present: bool,
    suid_bit: bool,
    sgid_bit: bool,
    world_writable_binary: bool,
    file_capabilities: Sequence[str],
    policy_blocked: bool,
) -> tuple[str, int, List[str]]:
    """Evaluate severity and numeric risk contribution for a binary finding."""
    if not present:
        return ("INFO", 0, ["Binary not present on host PATH."])

    notes: List[str] = []
    if policy_blocked:
        notes.append("Execution restricted by host application control policy (WDAC/AppLocker).")
        return ("LOW", max(1, entry.risk_weight // 4), notes)

    score = entry.risk_weight
    if world_writable_binary:
        score += 15
        notes.append("CRITICAL: Binary file itself is world-writable.")
    if suid_bit:
        score += 14
        notes.append("CRITICAL: SUID bit (04000) is set on dual-use administrative utility.")
    if sgid_bit:
        score += 8
        notes.append("HIGH: SGID bit (02000) is set on dual-use administrative utility.")
    if file_capabilities:
        score += 10
        notes.append(f"HIGH: Elevated Linux file capabilities detected ({', '.join(file_capabilities)}).")

    if suid_bit or world_writable_binary:
        severity = "CRITICAL"
    elif sgid_bit or file_capabilities or entry.risk_weight >= 9:
        severity = "HIGH"
        if not notes:
            notes.append("High-risk dual-use utility present without application control block policy.")
    elif entry.risk_weight >= 7:
        severity = "MEDIUM"
        notes.append("Dual-use administrative utility available in standard PATH.")
    else:
        severity = "LOW"
        notes.append("Standard utility present; verify command-line audit logging.")

    return (severity, score, notes)


def _finalize_scores(
    findings: Sequence[BinaryFinding],
    writable_path_dirs: Sequence[str],
    policy_enforcement: Dict[str, bool],
    scanned_os: str,
) -> tuple[int, int, str, List[str]]:
    """Calculate composite hardening_score (0-100), exposure_score (0-100), rating, and remediation steps."""
    raw_penalty = 0.0

    for finding in findings:
        if not finding.present:
            continue
        if finding.severity == "CRITICAL":
            raw_penalty += 18.0
        elif finding.severity == "HIGH":
            raw_penalty += 7.5
        elif finding.severity == "MEDIUM":
            raw_penalty += 3.0
        elif finding.severity == "LOW" and not finding.policy_blocked:
            raw_penalty += 1.5

    raw_penalty += len(writable_path_dirs) * 10.0

    if scanned_os == "windows":
        if not policy_enforcement.get("wdac_enforced", False) and not policy_enforcement.get("applocker_enforced", False):
            raw_penalty += 12.0
    else:
        if not policy_enforcement.get("auditd_execve_enabled", False):
            raw_penalty += 8.0

    exposure_score = max(0, min(100, int(round(raw_penalty))))
    hardening_score = 100 - exposure_score

    if exposure_score >= 75:
        risk_rating = "CRITICAL"
    elif exposure_score >= 50:
        risk_rating = "HIGH"
    elif exposure_score >= 25:
        risk_rating = "MODERATE"
    else:
        risk_rating = "LOW"

    remediation_plan: List[str] = []
    if writable_path_dirs:
        remediation_plan.append(
            f"Remove world-writable permissions or relative entries from PATH directories: {', '.join(writable_path_dirs)}"
        )

    for finding in findings:
        if finding.present and (finding.suid_bit or finding.sgid_bit):
            target = finding.resolved_path or finding.name
            remediation_plan.append(
                f"Strip SUID/SGID mode bits from {target}: chmod u-s,g-s {target}"
            )
        if finding.present and finding.file_capabilities:
            target = finding.resolved_path or finding.name
            remediation_plan.append(
                f"Remove elevated file capabilities from {target}: setcap -r {target}"
            )

    if scanned_os == "windows":
        if not policy_enforcement.get("wdac_enforced", False) and not policy_enforcement.get("applocker_enforced", False):
            remediation_plan.append(
                "Deploy Microsoft Recommended Block Rules via Windows Defender Application Control (WDAC) or AppLocker."
            )
    else:
        if not policy_enforcement.get("auditd_execve_enabled", False):
            remediation_plan.append(
                "Configure Linux auditd rules (-a always,exit -F arch=b64 -S execve,execveat) to log dual-use binary invocations."
            )

    for finding in findings:
        if finding.present and finding.severity in ("CRITICAL", "HIGH") and finding.hardening_controls:
            control = finding.hardening_controls[0]
            if control not in remediation_plan:
                remediation_plan.append(f"[{finding.name}] {control}")

    return hardening_score, exposure_score, risk_rating, remediation_plan


def scan_live_host(
    requested_os: str = "auto",
    search_paths: Optional[Sequence[str]] = None,
) -> ScanReport:
    """Perform a read-only posture scan of the local host."""
    scanned_os = detect_host_os(requested_os)
    catalog_entries = get_catalog(scanned_os)

    if search_paths is not None:
        path_list = list(search_paths)
        path_env = os.pathsep.join(path_list)
    else:
        path_env = os.environ.get("PATH", "")
        path_list = [p for p in path_env.split(os.pathsep) if p]

    writable_dirs = _audit_writable_path_dirs(path_list)

    if scanned_os == "windows":
        appdata = os.environ.get("SystemRoot", "C:\\Windows")
        applocker_dir = Path(appdata) / "System32" / "AppLocker"
        applocker_enforced = applocker_dir.exists() and any(applocker_dir.iterdir()) if applocker_dir.exists() else False
        policy_enforcement = {
            "wdac_enforced": False,
            "applocker_enforced": applocker_enforced,
            "sysmon_installed": Path(appdata, "System32", "drivers", "SysmonDrv.sys").exists(),
        }
    else:
        audit_rules = Path("/etc/audit/audit.rules")
        audit_d = Path("/etc/audit/rules.d")
        audit_configured = audit_rules.exists() or (audit_d.exists() and any(audit_d.iterdir()))
        policy_enforcement = {
            "auditd_execve_enabled": bool(audit_configured),
            "apparmor_or_selinux": Path("/sys/kernel/security/apparmor").exists() or Path("/sys/fs/selinux").exists(),
        }

    findings: List[BinaryFinding] = []
    for entry in catalog_entries:
        resolved = shutil.which(entry.name, path=path_env)
        if not resolved:
            findings.append(
                BinaryFinding(
                    name=entry.name,
                    target_os=entry.target_os,
                    present=False,
                    resolved_path=None,
                    sha256=None,
                    mode_octal=None,
                    suid_bit=False,
                    sgid_bit=False,
                    world_writable_binary=False,
                    file_capabilities=[],
                    policy_blocked=False,
                    severity="INFO",
                    risk_score=0,
                    mitre_techniques=list(entry.mitre_techniques),
                    hardening_controls=list(entry.hardening_controls),
                    notes=["Binary not present in scanned PATH."],
                )
            )
            continue

        resolved_path = Path(resolved)
        try:
            st = resolved_path.stat()
            mode = st.st_mode
            mode_octal = oct(stat.S_IMODE(mode))
            suid_bit = bool(mode & stat.S_ISUID)
            sgid_bit = bool(mode & stat.S_ISGID)
            world_writable_binary = bool(mode & stat.S_IWOTH)
        except OSError:
            mode_octal = None
            suid_bit = False
            sgid_bit = False
            world_writable_binary = False

        caps = _inspect_linux_capabilities(resolved_path) if scanned_os == "linux" else []
        sha256_hex = compute_file_sha256(resolved_path)

        severity, risk_score, notes = _classify_finding(
            entry=entry,
            present=True,
            suid_bit=suid_bit,
            sgid_bit=sgid_bit,
            world_writable_binary=world_writable_binary,
            file_capabilities=caps,
            policy_blocked=False,
        )

        findings.append(
            BinaryFinding(
                name=entry.name,
                target_os=entry.target_os,
                present=True,
                resolved_path=str(resolved_path),
                sha256=sha256_hex,
                mode_octal=mode_octal,
                suid_bit=suid_bit,
                sgid_bit=sgid_bit,
                world_writable_binary=world_writable_binary,
                file_capabilities=caps,
                policy_blocked=False,
                severity=severity,
                risk_score=risk_score,
                mitre_techniques=list(entry.mitre_techniques),
                hardening_controls=list(entry.hardening_controls),
                notes=notes,
            )
        )

    findings.sort(key=lambda f: (-f.risk_score, f.name))

    hardening_score, exposure_score, risk_rating, remediation_plan = _finalize_scores(
        findings=findings,
        writable_path_dirs=writable_dirs,
        policy_enforcement=policy_enforcement,
        scanned_os=scanned_os,
    )

    present_count = sum(1 for f in findings if f.present)
    high_risk_count = sum(1 for f in findings if f.present and f.severity in ("CRITICAL", "HIGH"))

    return ScanReport(
        hostname="localhost",
        scanned_os=scanned_os,
        scan_mode="live",
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        hardening_score=hardening_score,
        exposure_score=exposure_score,
        risk_rating=risk_rating,
        writable_path_dirs=writable_dirs,
        policy_enforcement=policy_enforcement,
        total_catalog_checked=len(findings),
        present_count=present_count,
        high_risk_count=high_risk_count,
        findings=findings,
        remediation_plan=remediation_plan,
    )


def scan_manifest_file(manifest_path: str | Path) -> ScanReport:
    """Evaluate an offline host inventory manifest JSON file."""
    path_obj = Path(manifest_path)
    raw_data = json.loads(path_obj.read_text(encoding="utf-8"))
    if not isinstance(raw_data, dict):
        raise ValueError("Host manifest root must be a JSON object.")

    scanned_os = str(raw_data.get("os", "linux")).lower().strip()
    if scanned_os not in ("linux", "windows"):
        raise ValueError(f"Unsupported manifest OS '{scanned_os}'; expected 'linux' or 'windows'.")

    hostname = str(raw_data.get("hostname", "offline-host"))
    writable_dirs = [str(d) for d in raw_data.get("writable_path_dirs", [])]
    policy_enforcement = {
        str(k): bool(v) for k, v in (raw_data.get("policy_enforcement") or {}).items()
    }

    manifest_binaries: Dict[str, Dict[str, Any]] = {}
    for item in raw_data.get("binaries", []):
        if isinstance(item, dict) and "name" in item:
            manifest_binaries[str(item["name"]).lower()] = item

    catalog_entries = get_catalog(scanned_os)
    findings: List[BinaryFinding] = []

    for entry in catalog_entries:
        record = manifest_binaries.get(entry.name.lower())
        if not record or not record.get("present", True):
            findings.append(
                BinaryFinding(
                    name=entry.name,
                    target_os=entry.target_os,
                    present=False,
                    resolved_path=None,
                    sha256=None,
                    mode_octal=None,
                    suid_bit=False,
                    sgid_bit=False,
                    world_writable_binary=False,
                    file_capabilities=[],
                    policy_blocked=False,
                    severity="INFO",
                    risk_score=0,
                    mitre_techniques=list(entry.mitre_techniques),
                    hardening_controls=list(entry.hardening_controls),
                    notes=["Binary marked absent in offline host manifest."],
                )
            )
            continue

        resolved_path = record.get("path")
        mode_octal = record.get("mode")
        suid_bit = bool(record.get("suid", False))
        sgid_bit = bool(record.get("sgid", False))
        if mode_octal and isinstance(mode_octal, str):
            try:
                parsed_mode = int(mode_octal, 8)
                suid_bit = suid_bit or bool(parsed_mode & stat.S_ISUID)
                sgid_bit = sgid_bit or bool(parsed_mode & stat.S_ISGID)
            except ValueError:
                pass

        world_writable_binary = bool(record.get("world_writable", False))
        caps = [str(c) for c in record.get("capabilities", [])]
        policy_blocked = bool(record.get("policy_blocked", False))
        sha256_hex = record.get("sha256")

        severity, risk_score, notes = _classify_finding(
            entry=entry,
            present=True,
            suid_bit=suid_bit,
            sgid_bit=sgid_bit,
            world_writable_binary=world_writable_binary,
            file_capabilities=caps,
            policy_blocked=policy_blocked,
        )

        findings.append(
            BinaryFinding(
                name=entry.name,
                target_os=entry.target_os,
                present=True,
                resolved_path=str(resolved_path) if resolved_path else None,
                sha256=str(sha256_hex) if sha256_hex else None,
                mode_octal=str(mode_octal) if mode_octal else None,
                suid_bit=suid_bit,
                sgid_bit=sgid_bit,
                world_writable_binary=world_writable_binary,
                file_capabilities=caps,
                policy_blocked=policy_blocked,
                severity=severity,
                risk_score=risk_score,
                mitre_techniques=list(entry.mitre_techniques),
                hardening_controls=list(entry.hardening_controls),
                notes=notes,
            )
        )

    findings.sort(key=lambda f: (-f.risk_score, f.name))

    hardening_score, exposure_score, risk_rating, remediation_plan = _finalize_scores(
        findings=findings,
        writable_path_dirs=writable_dirs,
        policy_enforcement=policy_enforcement,
        scanned_os=scanned_os,
    )

    present_count = sum(1 for f in findings if f.present)
    high_risk_count = sum(1 for f in findings if f.present and f.severity in ("CRITICAL", "HIGH"))

    return ScanReport(
        hostname=hostname,
        scanned_os=scanned_os,
        scan_mode="manifest",
        timestamp_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        hardening_score=hardening_score,
        exposure_score=exposure_score,
        risk_rating=risk_rating,
        writable_path_dirs=writable_dirs,
        policy_enforcement=policy_enforcement,
        total_catalog_checked=len(findings),
        present_count=present_count,
        high_risk_count=high_risk_count,
        findings=findings,
        remediation_plan=remediation_plan,
    )
