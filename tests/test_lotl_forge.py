"""Unit test suite for lotl-forge."""

from __future__ import annotations

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lotl_forge.catalog import (
    CATALOG,
    filter_by_technique,
    get_catalog,
    get_entry_by_name,
)
from lotl_forge.cli import main as cli_main
from lotl_forge.exporter import (
    build_navigator_layer,
    export_json_audit,
    export_markdown_report,
    export_navigator_layer,
)
from lotl_forge.scanner import (
    detect_host_os,
    scan_live_host,
    scan_manifest_file,
)
from lotl_forge.simulator import (
    run_telemetry_verification,
    verify_record_signature,
)


class TestLotlForgeSuite(unittest.TestCase):
    """Comprehensive behavioral tests for catalog, scanner, simulator, exporter, and CLI."""

    def test_01_catalog_completeness_and_dual_os_coverage(self) -> None:
        self.assertGreaterEqual(len(CATALOG), 25)
        win_entries = get_catalog("windows")
        lin_entries = get_catalog("linux")
        self.assertGreaterEqual(len(win_entries), 13)
        self.assertGreaterEqual(len(lin_entries), 14)

        for entry in CATALOG:
            self.assertIn(entry.target_os, ("windows", "linux"))
            self.assertTrue(entry.administrative_purpose)
            self.assertTrue(entry.capabilities)
            self.assertTrue(entry.mitre_techniques)
            self.assertTrue(entry.hardening_controls)
            self.assertIn("source", entry.expected_telemetry)
            self.assertIn("detection:", entry.sigma_snippet)
            self.assertGreaterEqual(len(entry.safe_probe_args), 2)

    def test_02_catalog_lookup_and_mitre_filtering(self) -> None:
        certutil = get_entry_by_name("CERTUTIL.EXE")
        self.assertIsNotNone(certutil)
        assert certutil is not None
        self.assertEqual(certutil.target_os, "windows")
        self.assertIn("T1105", certutil.mitre_techniques)

        t1218_matches = filter_by_technique("T1218", target_os="windows")
        names = {m.name for m in t1218_matches}
        self.assertIn("mshta.exe", names)
        self.assertIn("rundll32.exe", names)
        self.assertIn("regsvr32.exe", names)

        t1548_matches = filter_by_technique("T1548.001", target_os="linux")
        self.assertGreaterEqual(len(t1548_matches), 8)

    def test_03_detect_host_os_override_and_auto(self) -> None:
        self.assertEqual(detect_host_os("linux"), "linux")
        self.assertEqual(detect_host_os("WINDOWS"), "windows")
        with mock.patch("platform.system", return_value="Windows"):
            self.assertEqual(detect_host_os("auto"), "windows")
        with mock.patch("platform.system", return_value="Linux"):
            self.assertEqual(detect_host_os("auto"), "linux")

    def test_04_linux_live_scan_suid_and_writable_path_detection(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            # Create a dummy python3 binary with SUID bit enabled
            fake_bin = tmp_path / "python3"
            fake_bin.write_bytes(b"#!/bin/sh\necho Python 3.12.0\n")
            os.chmod(fake_bin, 0o4755)
            # Make directory world-writable without sticky bit
            os.chmod(tmp_path, 0o777)

            st_mode = fake_bin.stat().st_mode
            has_suid_support = bool(st_mode & stat.S_ISUID)

            report = scan_live_host(requested_os="linux", search_paths=[ str(tmp_path) ])
            self.assertEqual(report.scanned_os, "linux")
            self.assertIn(str(tmp_path), report.writable_path_dirs)

            py_finding = next(f for f in report.findings if f.name == "python3")
            self.assertTrue(py_finding.present)
            self.assertIsNotNone(py_finding.sha256)
            if has_suid_support:
                self.assertTrue(py_finding.suid_bit)
                self.assertEqual(py_finding.severity, "CRITICAL")

    def test_05_simulated_windows_live_scan(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            for name in ("mshta.exe", "certutil.exe", "powershell.exe"):
                binary_file = tmp_path / name
                binary_file.write_bytes(b"MZ-pe-stub-for-posture-testing")
                os.chmod(binary_file, 0o755)

            report = scan_live_host(requested_os="windows", search_paths=[str(tmp_path)])
            self.assertEqual(report.scanned_os, "windows")
            self.assertEqual(report.present_count, 3)
            mshta = next(f for f in report.findings if f.name == "mshta.exe")
            self.assertTrue(mshta.present)
            self.assertEqual(mshta.severity, "HIGH")
            self.assertLess(report.hardening_score, 100)
            self.assertEqual(report.hardening_score + report.exposure_score, 100)

    def test_06_offline_manifest_scan_windows_and_linux(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        win_manifest = repo_root / "samples" / "windows_server_manifest.json"
        lin_manifest = repo_root / "samples" / "linux_prod_manifest.json"

        win_report = scan_manifest_file(win_manifest)
        self.assertEqual(win_report.scanned_os, "windows")
        self.assertEqual(win_report.present_count, 8)
        bits = next(f for f in win_report.findings if f.name == "bitsadmin.exe")
        self.assertTrue(bits.policy_blocked)
        self.assertEqual(bits.severity, "LOW")

        lin_report = scan_manifest_file(lin_manifest)
        self.assertEqual(lin_report.scanned_os, "linux")
        self.assertEqual(lin_report.risk_rating, "CRITICAL")
        py_find = next(f for f in lin_report.findings if f.name == "python3")
        self.assertTrue(py_find.suid_bit)
        self.assertEqual(py_find.severity, "CRITICAL")

    def test_07_simulator_authorization_gate_enforced(self) -> None:
        with self.assertRaises(PermissionError):
            run_telemetry_verification(confirm_authorized_scope=False)

    def test_08_simulator_dry_run_and_hmac_verification(self) -> None:
        secret = b"unit-test-constant-time-hmac-secret"
        records = run_telemetry_verification(
            confirm_authorized_scope=True,
            requested_os="windows",
            technique_filter="T1218",
            dry_run=True,
            hmac_key=secret,
        )
        self.assertGreaterEqual(len(records), 4)
        for rec in records:
            self.assertEqual(rec.execution_mode, "dry-run-synthetic")
            self.assertTrue(verify_record_signature(rec, secret))
            self.assertFalse(verify_record_signature(rec, b"wrong-secret"))
            self.assertEqual(
                rec.synthetic_siem_event.get("EventChannel"),
                "Microsoft-Windows-Sysmon/Operational",
            )

    def test_09_simulator_live_benign_version_probe(self) -> None:
        records = run_telemetry_verification(
            confirm_authorized_scope=True,
            requested_os="linux",
            technique_filter="T1059.006",
            dry_run=False,
        )
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.binary_name, "python3")
        self.assertIn(rec.execution_mode, ("live-version-probe", "dry-run-synthetic"))
        self.assertEqual(rec.synthetic_siem_event.get("log_source"), "linux-auditd")

    def test_10_mitre_navigator_layer_v45_schema_compliance(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        lin_report = scan_manifest_file(repo_root / "samples" / "linux_prod_manifest.json")
        layer = build_navigator_layer(scan_report=lin_report)

        self.assertEqual(layer["versions"]["layer"], "4.5")
        self.assertEqual(layer["versions"]["attack"], "15")
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertIsInstance(layer["techniques"], list)
        self.assertGreaterEqual(len(layer["techniques"]), 3)
        tech_ids = {t["techniqueID"] for t in layer["techniques"]}
        self.assertIn("T1548.001", tech_ids)

    def test_11_exporters_write_valid_artifacts(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        report = scan_manifest_file(repo_root / "samples" / "windows_server_manifest.json")
        records = run_telemetry_verification(
            confirm_authorized_scope=True,
            requested_os="windows",
            technique_filter="T1105",
            dry_run=True,
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp_path = Path(tmpdir)
            nav_path = export_navigator_layer(tmp_path / "layer.json", report, records)
            json_path = export_json_audit(tmp_path / "audit.json", report, records)
            md_path = export_markdown_report(tmp_path / "report.md", report, records)

            self.assertTrue(nav_path.is_file())
            self.assertTrue(json_path.is_file())
            self.assertTrue(md_path.is_file())

            parsed_json = json.loads(json_path.read_text(encoding="utf-8"))
            self.assertIn("scan_report", parsed_json)
            self.assertIn("telemetry_records", parsed_json)

            md_text = md_path.read_text(encoding="utf-8")
            self.assertIn("## 1. Executive Posture Summary", md_text)
            self.assertIn("## 4. SIEM Telemetry Verification Audit Log", md_text)

    def test_12_cli_subcommands_and_error_handling(self) -> None:
        # Valid catalog query
        rc_cat = cli_main(["catalog", "--os", "windows", "--technique", "T1218"])
        self.assertEqual(rc_cat, 0)

        # Valid single binary lookup
        rc_bin = cli_main(["catalog", "--binary", "certutil.exe"])
        self.assertEqual(rc_bin, 0)

        # Unknown binary returns exit code 2
        rc_missing = cli_main(["catalog", "--binary", "nonexistent_utility.exe"])
        self.assertEqual(rc_missing, 2)

        # Simulate without --confirm-authorized-scope returns exit code 2
        rc_unauth = cli_main(["simulate", "--dry-run"])
        self.assertEqual(rc_unauth, 2)

        # Authorized dry-run simulation succeeds
        rc_sim = cli_main(["simulate", "--confirm-authorized-scope", "--dry-run", "--technique", "T1105"])
        self.assertEqual(rc_sim, 0)

    def test_13_zero_leak_repository_invariant(self) -> None:
        repo_root = Path(__file__).resolve().parent.parent
        forbidden_home_prefix = "/" + "home" + "/"
        for file_path in repo_root.rglob("*"):
            if not file_path.is_file() or ".git" in file_path.parts or "__pycache__" in file_path.parts:
                continue
            text = file_path.read_text(encoding="utf-8", errors="ignore")
            self.assertNotIn(
                forbidden_home_prefix,
                text,
                f"Forbidden local path prefix found in {file_path.name}",
            )


if __name__ == "__main__":
    unittest.main()
