"""Command-line interface for lotl-forge."""

from __future__ import annotations

import argparse
import sys
from typing import List, Optional, Sequence

from lotl_forge import __version__
from lotl_forge.catalog import filter_by_technique, get_catalog, get_entry_by_name
from lotl_forge.exporter import (
    export_json_audit,
    export_markdown_report,
    export_navigator_layer,
)
from lotl_forge.scanner import ScanReport, scan_live_host, scan_manifest_file
from lotl_forge.simulator import run_telemetry_verification


def _add_export_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--navigator-out",
        metavar="PATH",
        help="Write MITRE ATT&CK Navigator v4.5 JSON layer to PATH.",
    )
    parser.add_argument(
        "--json-out",
        metavar="PATH",
        help="Write structured JSON audit log to PATH.",
    )
    parser.add_argument(
        "--markdown-out",
        metavar="PATH",
        help="Write Markdown hardening & telemetry report to PATH.",
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lotl-forge",
        description=(
            "Cross-Platform Dual-Use Binary Hardening & SIEM Telemetry Verification Auditor"
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"lotl-forge {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # catalog subcommand
    cat_parser = subparsers.add_parser(
        "catalog",
        help="Query the curated dual-OS administrative binary intelligence database.",
    )
    cat_parser.add_argument(
        "--os",
        choices=["all", "linux", "windows"],
        default="all",
        help="Filter catalog entries by target operating system (default: all).",
    )
    cat_parser.add_argument(
        "--technique",
        metavar="TECHNIQUE_ID",
        help="Filter catalog entries by MITRE ATT&CK technique ID (e.g. T1218, T1548.001).",
    )
    cat_parser.add_argument(
        "--binary",
        metavar="NAME",
        help="Display detailed hardening & Sigma detection guidance for a specific binary.",
    )

    # scan subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Audit local host PATH or an offline JSON host manifest for binary posture risks.",
    )
    scan_parser.add_argument(
        "--os",
        choices=["auto", "linux", "windows"],
        default="auto",
        help="Target OS profile for live scan (default: auto).",
    )
    scan_parser.add_argument(
        "--manifest",
        metavar="PATH",
        help="Scan an offline host inventory JSON manifest instead of the live filesystem.",
    )
    _add_export_arguments(scan_parser)

    # simulate subcommand
    sim_parser = subparsers.add_parser(
        "simulate",
        help="Run safe version/help probes or emit synthetic SIEM events to verify telemetry.",
    )
    sim_parser.add_argument(
        "--confirm-authorized-scope",
        action="store_true",
        help="Required safety gate confirming authorization to generate SIEM test telemetry.",
    )
    sim_parser.add_argument(
        "--os",
        choices=["auto", "linux", "windows"],
        default="auto",
        help="Target OS catalog to verify (default: auto).",
    )
    sim_parser.add_argument(
        "--technique",
        metavar="TECHNIQUE_ID",
        help="Limit telemetry verification to a specific MITRE ATT&CK technique (e.g. T1218).",
    )
    sim_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Emit synthetic SIEM events without spawning any local child processes.",
    )
    _add_export_arguments(sim_parser)

    return parser


def _print_scan_summary(report: ScanReport) -> None:
    print("=" * 78)
    print(f"LOTL-FORGE ENDPOINT POSTURE AUDIT | HOST: {report.hostname} ({report.scanned_os.upper()})")
    print("=" * 78)
    print(f"Scan Mode              : {report.scan_mode}")
    print(f"Timestamp (UTC)        : {report.timestamp_utc}")
    print(f"Host Hardening Score   : {report.hardening_score}/100")
    print(f"Host Exposure Score    : {report.exposure_score}/100 [{report.risk_rating}]")
    print(f"Catalog Utilities Found: {report.present_count}/{report.total_catalog_checked}")
    print(f"High/Critical Findings : {report.high_risk_count}")
    print(f"Writable PATH Entries  : {len(report.writable_path_dirs)}")
    print("-" * 78)
    print(f"{'BINARY':<18} {'PRESENT':<8} {'SEVERITY':<10} {'SCORE':<6} {'MITRE ATT&CK':<20} {'NOTES'}")
    print("-" * 78)
    for finding in report.findings:
        if not finding.present:
            continue
        techs = ",".join(finding.mitre_techniques)
        note = finding.notes[0] if finding.notes else ""
        print(
            f"{finding.name:<18} {'YES':<8} {finding.severity:<10} "
            f"{finding.risk_score:<6} {techs:<20} {note[:38]}"
        )
    print("-" * 78)
    if report.remediation_plan:
        print("PRIORITIZED HARDENING REMEDIATIONS:")
        for idx, item in enumerate(report.remediation_plan[:8], start=1):
            print(f"  {idx}. {item}")
    print("=" * 78)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "catalog":
        if args.binary:
            entry = get_entry_by_name(args.binary)
            if not entry:
                print(f"Error: Binary '{args.binary}' not found in catalog.", file=sys.stderr)
                return 2
            print(f"Binary                : {entry.name} ({entry.target_os})")
            print(f"Administrative Purpose: {entry.administrative_purpose}")
            print(f"Capabilities          : {', '.join(entry.capabilities)}")
            print(f"MITRE ATT&CK          : {', '.join(entry.mitre_techniques)}")
            print(f"Baseline Risk Weight  : {entry.risk_weight}/10")
            print("Hardening Controls    :")
            for ctrl in entry.hardening_controls:
                print(f"  - {ctrl}")
            print("Sigma Detection Logic :")
            for line in entry.sigma_snippet.splitlines():
                print(f"  {line}")
            return 0

        target_os = None if args.os == "all" else args.os
        if args.technique:
            entries = filter_by_technique(args.technique, target_os=target_os)
        else:
            entries = get_catalog(target_os)

        print(f"{'BINARY':<18} {'OS':<9} {'WEIGHT':<7} {'MITRE ATT&CK':<22} {'CAPABILITIES'}")
        print("-" * 88)
        for entry in entries:
            print(
                f"{entry.name:<18} {entry.target_os:<9} {entry.risk_weight:<7} "
                f"{','.join(entry.mitre_techniques):<22} {','.join(entry.capabilities)}"
            )
        print("-" * 88)
        print(f"Total catalog entries matched: {len(entries)}")
        return 0

    if args.command == "scan":
        try:
            if args.manifest:
                report = scan_manifest_file(args.manifest)
            else:
                report = scan_live_host(requested_os=args.os)
        except (OSError, ValueError) as exc:
            print(f"Error during posture scan: {exc}", file=sys.stderr)
            return 2

        _print_scan_summary(report)

        if args.navigator_out:
            export_navigator_layer(args.navigator_out, scan_report=report)
            print(f"[+] Wrote MITRE ATT&CK Navigator v4.5 layer to {args.navigator_out}")
        if args.json_out:
            export_json_audit(args.json_out, scan_report=report)
            print(f"[+] Wrote JSON posture audit report to {args.json_out}")
        if args.markdown_out:
            export_markdown_report(args.markdown_out, scan_report=report)
            print(f"[+] Wrote Markdown hardening report to {args.markdown_out}")
        return 0

    if args.command == "simulate":
        if not args.confirm_authorized_scope:
            print(
                "Error: Telemetry verification requires explicit --confirm-authorized-scope flag.",
                file=sys.stderr,
            )
            return 2

        records = run_telemetry_verification(
            confirm_authorized_scope=True,
            requested_os=args.os,
            technique_filter=args.technique,
            dry_run=args.dry_run,
        )
        print("=" * 84)
        print(f"LOTL-FORGE SIEM TELEMETRY VERIFICATION | RECORDS GENERATED: {len(records)}")
        print("=" * 84)
        print(f"{'BINARY':<18} {'MODE':<20} {'PID':<8} {'EXIT':<6} {'MITRE ATT&CK':<18} {'HMAC PREFIX'}")
        print("-" * 84)
        for rec in records:
            pid_str = str(rec.pid) if rec.pid is not None else "SYNTH"
            exit_str = str(rec.exit_code) if rec.exit_code is not None else "-"
            tech_str = ",".join(rec.mitre_techniques)
            print(
                f"{rec.binary_name:<18} {rec.execution_mode:<20} {pid_str:<8} "
                f"{exit_str:<6} {tech_str:<18} {rec.record_hmac_sha256[:12]}"
            )
        print("=" * 84)

        if args.navigator_out:
            export_navigator_layer(args.navigator_out, telemetry_records=records)
            print(f"[+] Wrote MITRE ATT&CK Navigator v4.5 layer to {args.navigator_out}")
        if args.json_out:
            export_json_audit(args.json_out, telemetry_records=records)
            print(f"[+] Wrote JSON telemetry audit log to {args.json_out}")
        if args.markdown_out:
            export_markdown_report(args.markdown_out, telemetry_records=records)
            print(f"[+] Wrote Markdown telemetry report to {args.markdown_out}")
        return 0

    return 1


if __name__ == "__main__":
    sys.exit(main())
