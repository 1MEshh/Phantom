"""Curated dual-OS reference catalog of administrative dual-use binaries.

Documents legitimate administrative functionality, associated MITRE ATT&CK v15
techniques for detection mapping, recommended endpoint hardening controls
(AppLocker/WDAC on Windows, SUID removal and mount restrictions on Linux),
expected SIEM/Sysmon/Auditd telemetry fields, Sigma detection logic snippets,
and strictly non-destructive version/help probe arguments for SIEM pipeline
verification.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Sequence


@dataclass(frozen=True)
class BinaryEntry:
    """Metadata record for a single dual-use system utility."""

    name: str
    target_os: str  # "windows" | "linux"
    administrative_purpose: str
    capabilities: Sequence[str]
    mitre_techniques: Sequence[str]
    risk_weight: int  # 1-10 baseline exposure weight
    hardening_controls: Sequence[str]
    expected_telemetry: Dict[str, Any]
    sigma_snippet: str
    safe_probe_args: Sequence[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


CATALOG: List[BinaryEntry] = [
    # -------------------------------------------------------------------------
    # Windows Administrative Utilities (13 entries)
    # -------------------------------------------------------------------------
    BinaryEntry(
        name="certutil.exe",
        target_os="windows",
        administrative_purpose=(
            "Command-line program installed as part of Certificate Services to dump "
            "and display certification authority (CA) configuration information, "
            "configure Certificate Services, and verify certificates and key pairs."
        ),
        capabilities=("file-transfer", "encoding-decoding", "certificate-management"),
        mitre_techniques=("T1105", "T1140"),
        risk_weight=9,
        hardening_controls=(
            "Enforce Windows Defender Application Control (WDAC) or AppLocker rules "
            "restricting certutil.exe execution to PKI administrators.",
            "Monitor outbound network connections initiated by certutil.exe via Windows Filtering Platform.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 3, 11],
            "fields": ["Image", "CommandLine", "ParentImage", "Hashes", "DestinationIp"],
            "audit_flags": ["-urlcache", "-verifyctl", "-encode", "-decode", "-encodehex"],
        },
        sigma_snippet=(
            "title: Suspicious Certutil Network or Decode Activity\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\certutil.exe'\n"
            "    CommandLine|contains:\n"
            "      - 'urlcache'\n"
            "      - 'verifyctl'\n"
            "      - 'decode'\n"
            "  condition: selection"
        ),
        safe_probe_args=["certutil.exe", "-?"],
    ),
    BinaryEntry(
        name="mshta.exe",
        target_os="windows",
        administrative_purpose=(
            "Microsoft HTML Application Host utility responsible for executing "
            "legacy .hta administrative interfaces backed by Windows Script Host."
        ),
        capabilities=("script-host-execution", "remote-resource-loading"),
        mitre_techniques=("T1218.005", "T1059.005"),
        risk_weight=10,
        hardening_controls=(
            "Block mshta.exe execution enterprise-wide via WDAC user-mode block rules "
            "or AppLocker EXE rules unless explicitly required for legacy applications.",
            "Enable Attack Surface Reduction (ASR) rule to block Office applications from spawning child processes.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 3, 7],
            "fields": ["Image", "CommandLine", "ParentImage", "ImageLoaded"],
            "audit_flags": ["vbscript:", "javascript:", "http://", "https://"],
        },
        sigma_snippet=(
            "title: MSHTA Inline Script or Network Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\mshta.exe'\n"
            "  condition: selection"
        ),
        safe_probe_args=["mshta.exe", "/?"],
    ),
    BinaryEntry(
        name="rundll32.exe",
        target_os="windows",
        administrative_purpose=(
            "Windows host process designed to invoke exported functions inside "
            "16-bit or 32/64-bit dynamic-link libraries (DLLs) from the command line."
        ),
        capabilities=("dll-export-invocation", "control-panel-applet-loading"),
        mitre_techniques=("T1218.011",),
        risk_weight=8,
        hardening_controls=(
            "Enable WDAC DLL enforcement so rundll32.exe can only load signed, trusted DLLs.",
            "Audit rundll32.exe executions lacking a valid file path or referencing network shares.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 7],
            "fields": ["Image", "CommandLine", "ImageLoaded", "Signed", "SignatureStatus"],
            "audit_flags": ["javascript:", "url.dll", "zipfldr.dll", "comsvcs.dll"],
        },
        sigma_snippet=(
            "title: Rundll32 Unusual CommandLine Invocation\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\rundll32.exe'\n"
            "    CommandLine|contains:\n"
            "      - 'comsvcs'\n"
            "      - 'url.dll'\n"
            "      - 'javascript:'\n"
            "  condition: selection"
        ),
        safe_probe_args=["rundll32.exe", "/?"],
    ),
    BinaryEntry(
        name="regsvr32.exe",
        target_os="windows",
        administrative_purpose=(
            "Command-line utility used by software installers and administrators to "
            "register and unregister OLE controls, such as DLLs and ActiveX controls, "
            "in the Windows Registry."
        ),
        capabilities=("com-registration", "scriptlet-processing"),
        mitre_techniques=("T1218.010",),
        risk_weight=9,
        hardening_controls=(
            "Restrict scrobj.dll loading or block outbound network access from regsvr32.exe via Windows Firewall.",
            "Enforce AppLocker DLL rules to prevent registration of unsigned binaries from user-writable directories.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 3, 7],
            "fields": ["Image", "CommandLine", "ImageLoaded", "DestinationIp"],
            "audit_flags": ["/s", "/u", "/i:", "scrobj.dll"],
        },
        sigma_snippet=(
            "title: Regsvr32 Scriptlet or Remote Object Registration\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\regsvr32.exe'\n"
            "    CommandLine|contains: '/i:'\n"
            "  condition: selection"
        ),
        safe_probe_args=["regsvr32.exe", "/?"],
    ),
    BinaryEntry(
        name="bitsadmin.exe",
        target_os="windows",
        administrative_purpose=(
            "Legacy command-line tool used to create, download, or upload Background "
            "Intelligent Transfer Service (BITS) jobs and monitor their progress."
        ),
        capabilities=("background-file-transfer", "job-notification-execution"),
        mitre_techniques=("T1197", "T1105"),
        risk_weight=8,
        hardening_controls=(
            "Deprecate and block bitsadmin.exe via AppLocker/WDAC in favor of constrained PowerShell BITS cmdlets.",
            "Monitor Microsoft-Windows-Bits-Client/Operational Event IDs 3, 59, and 60.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 3],
            "fields": ["Image", "CommandLine", "DestinationHostname"],
            "audit_flags": ["/transfer", "/create", "/addfile", "/SetNotifyCmdLine"],
        },
        sigma_snippet=(
            "title: Bitsadmin Job Creation or Notify Command\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\bitsadmin.exe'\n"
            "    CommandLine|contains:\n"
            "      - '/transfer'\n"
            "      - '/SetNotifyCmdLine'\n"
            "  condition: selection"
        ),
        safe_probe_args=["bitsadmin.exe", "/?"],
    ),
    BinaryEntry(
        name="wmic.exe",
        target_os="windows",
        administrative_purpose=(
            "Windows Management Instrumentation Command-line utility providing "
            "a CLI interface to local and remote WMI namespaces for system inventory and configuration."
        ),
        capabilities=("wmi-query-execution", "xsl-stylesheet-processing"),
        mitre_techniques=("T1047", "T1220"),
        risk_weight=8,
        hardening_controls=(
            "Remove the deprecated WMIC Feature on Demand (FoD) package on Windows 11 and Windows Server 2025.",
            "Block WMIC execution for standard non-administrative users via WDAC.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 19, 20, 21],
            "fields": ["Image", "CommandLine", "User", "ParentImage"],
            "audit_flags": ["process call create", "/format:", "/node:"],
        },
        sigma_snippet=(
            "title: WMIC Process Creation or XSL Format Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\wmic.exe'\n"
            "    CommandLine|contains:\n"
            "      - 'process call create'\n"
            "      - '/format:'\n"
            "  condition: selection"
        ),
        safe_probe_args=["wmic.exe", "/?"],
    ),
    BinaryEntry(
        name="msiexec.exe",
        target_os="windows",
        administrative_purpose=(
            "Windows Installer component responsible for installing, maintaining, "
            "and removing MSI software packages and patches."
        ),
        capabilities=("package-installation", "remote-msi-retrieval"),
        mitre_techniques=("T1218.007",),
        risk_weight=7,
        hardening_controls=(
            "Disable AlwaysInstallElevated in both HKLM and HKCU Group Policy paths.",
            "Enforce AppLocker Windows Installer rules requiring digitally signed MSI packages.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 3, 11],
            "fields": ["Image", "CommandLine", "ParentImage"],
            "audit_flags": ["/q", "/i http", "/y", "/z"],
        },
        sigma_snippet=(
            "title: Msiexec Quiet or Remote Package Installation\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\msiexec.exe'\n"
            "    CommandLine|contains:\n"
            "      - 'http://'\n"
            "      - 'https://'\n"
            "  condition: selection"
        ),
        safe_probe_args=["msiexec.exe", "/?"],
    ),
    BinaryEntry(
        name="cmstp.exe",
        target_os="windows",
        administrative_purpose=(
            "Microsoft Connection Manager Profile Installer utility used to install "
            "or remove Connection Manager service profiles via INF configuration files."
        ),
        capabilities=("inf-profile-installation", "com-auto-elevation"),
        mitre_techniques=("T1218.003",),
        risk_weight=9,
        hardening_controls=(
            "Block cmstp.exe in WDAC recommended block rules unless legacy dial-up/VPN profiles are actively managed.",
            "Monitor Sysmon Event ID 1 for cmstp.exe running with /s or /au flags.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 7, 10],
            "fields": ["Image", "CommandLine", "ParentImage"],
            "audit_flags": ["/s", "/au", "/ni", ".inf"],
        },
        sigma_snippet=(
            "title: CMSTP Silent INF Profile Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\cmstp.exe'\n"
            "    CommandLine|contains:\n"
            "      - '/s'\n"
            "      - '/au'\n"
            "  condition: selection"
        ),
        safe_probe_args=["cmstp.exe", "/?"],
    ),
    BinaryEntry(
        name="forfiles.exe",
        target_os="windows",
        administrative_purpose=(
            "Batch-processing command utility that selects files in a directory tree "
            "and runs a specified command on each matching file."
        ),
        capabilities=("indirect-command-invocation", "batch-file-iteration"),
        mitre_techniques=("T1202",),
        risk_weight=6,
        hardening_controls=(
            "Audit child processes spawned by forfiles.exe via Sysmon Event ID 1 ParentImage correlation.",
            "Restrict interactive command utilities on hardened jump hosts.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1],
            "fields": ["Image", "CommandLine", "ParentImage"],
            "audit_flags": ["/c", "/m", "/p"],
        },
        sigma_snippet=(
            "title: Forfiles Indirect Command Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\forfiles.exe'\n"
            "    CommandLine|contains: '/c '\n"
            "  condition: selection"
        ),
        safe_probe_args=["forfiles.exe", "/?"],
    ),
    BinaryEntry(
        name="pcalua.exe",
        target_os="windows",
        administrative_purpose=(
            "Program Compatibility Assistant utility that assists in launching legacy "
            "applications with compatibility shims applied."
        ),
        capabilities=("indirect-command-invocation",),
        mitre_techniques=("T1202",),
        risk_weight=6,
        hardening_controls=(
            "Include pcalua.exe in process creation telemetry rules looking for -a command-line forwarding.",
            "Block pcalua.exe execution on headless server roles.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1],
            "fields": ["Image", "CommandLine", "ParentImage"],
            "audit_flags": ["-a", "-c"],
        },
        sigma_snippet=(
            "title: Program Compatibility Assistant Indirect Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\pcalua.exe'\n"
            "    CommandLine|contains: '-a'\n"
            "  condition: selection"
        ),
        safe_probe_args=["pcalua.exe", "/?"],
    ),
    BinaryEntry(
        name="powershell.exe",
        target_os="windows",
        administrative_purpose=(
            "Task-based command-line shell and scripting language built on .NET "
            "for enterprise Windows administration and configuration management."
        ),
        capabilities=("script-host-execution", "dotnet-reflection", "remote-management"),
        mitre_techniques=("T1059.001",),
        risk_weight=8,
        hardening_controls=(
            "Enforce Constrained Language Mode (CLM) via WDAC policy for non-administrative sessions.",
            "Enable Script Block Logging (Event ID 4104), Module Logging (4103), and Transcription via GPO.",
            "Remove Windows PowerShell 2.0 Engine feature to prevent downgrade bypasses.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-PowerShell/Operational",
            "event_ids": [4103, 4104],
            "fields": ["ScriptBlockText", "Path", "HostApplication", "ContextInfo"],
            "audit_flags": ["-EncodedCommand", "-enc", "-nop", "-w hidden", "DownloadString"],
        },
        sigma_snippet=(
            "title: PowerShell Encoded or Hidden Window Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\powershell.exe'\n"
            "    CommandLine|contains:\n"
            "      - '-enc'\n"
            "      - '-w hidden'\n"
            "  condition: selection"
        ),
        safe_probe_args=["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "$PSVersionTable.PSVersion.ToString()"],
    ),
    BinaryEntry(
        name="csc.exe",
        target_os="windows",
        administrative_purpose=(
            "Microsoft .NET Framework C# command-line compiler installed within "
            "C:\\Windows\\Microsoft.NET\\Framework directories."
        ),
        capabilities=("local-code-compilation",),
        mitre_techniques=("T1027.004",),
        risk_weight=7,
        hardening_controls=(
            "Block csc.exe in Microsoft recommended WDAC block rules on production endpoints that do not compile code.",
            "Enforce signed code execution policies so freshly compiled unsigned binaries cannot run.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 11],
            "fields": ["Image", "CommandLine", "ParentImage", "TargetFilename"],
            "audit_flags": ["/out:", "/target:library", "/noconfig"],
        },
        sigma_snippet=(
            "title: DotNet CSharp Compiler Execution on Endpoint\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\csc.exe'\n"
            "  condition: selection"
        ),
        safe_probe_args=["csc.exe", "/help"],
    ),
    BinaryEntry(
        name="installutil.exe",
        target_os="windows",
        administrative_purpose=(
            ".NET Framework Installer tool that allows administrators to install "
            "and uninstall server resources by executing installer components in specified assemblies."
        ),
        capabilities=("assembly-installer-execution",),
        mitre_techniques=("T1218.004",),
        risk_weight=9,
        hardening_controls=(
            "Block InstallUtil.exe via WDAC/AppLocker rules on non-developer workstations and servers.",
            "Audit invocations containing /logfile= or /U flags pointing to user-writable directories.",
        ),
        expected_telemetry={
            "source": "Microsoft-Windows-Sysmon/Operational",
            "event_ids": [1, 7],
            "fields": ["Image", "CommandLine", "ImageLoaded"],
            "audit_flags": ["/logfile=", "/LogToConsole=false", "/U"],
        },
        sigma_snippet=(
            "title: InstallUtil Uninstall Handler Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: windows\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '\\InstallUtil.exe'\n"
            "    CommandLine|contains: '/U'\n"
            "  condition: selection"
        ),
        safe_probe_args=["installutil.exe", "/?"],
    ),
    # -------------------------------------------------------------------------
    # Linux Administrative Utilities (14 entries)
    # -------------------------------------------------------------------------
    BinaryEntry(
        name="python3",
        target_os="linux",
        administrative_purpose=(
            "General-purpose high-level scripting interpreter used by system "
            "management tools, package managers, and automation frameworks."
        ),
        capabilities=("script-interpreter", "network-socket-client", "suid-privilege-risk"),
        mitre_techniques=("T1059.006", "T1548.001"),
        risk_weight=8,
        hardening_controls=(
            "Ensure python3 never carries SUID/SGID mode bits (chmod u-s,g-s /usr/bin/python3*) "
            "or elevated Linux file capabilities (setcap -r).",
            "Remove interactive interpreters from minimal distroless production containers.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve", "execveat", "socket", "connect"],
            "fields": ["exe", "proctitle", "uid", "euid", "auid", "ppid"],
            "audit_flags": ["-c", "pty.spawn", "socket", "urllib"],
        },
        sigma_snippet=(
            "title: Python Inline Command Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/python3'\n"
            "    CommandLine|contains: ' -c '\n"
            "  condition: selection"
        ),
        safe_probe_args=["python3", "--version"],
    ),
    BinaryEntry(
        name="tar",
        target_os="linux",
        administrative_purpose=(
            "Standard POSIX tape archiver utility used for creating, maintaining, "
            "modifying, and extracting file archives."
        ),
        capabilities=("archive-extraction", "checkpoint-action-hook", "suid-privilege-risk"),
        mitre_techniques=("T1548.001", "T1059.004"),
        risk_weight=7,
        hardening_controls=(
            "Avoid granting blanket sudo NOPASSWD permissions to /bin/tar or wildcard arguments.",
            "Verify /bin/tar has no SUID bit or cap_dac_read_search file capability unless strictly audited.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["--checkpoint", "--checkpoint-action", "--to-command"],
        },
        sigma_snippet=(
            "title: Tar Checkpoint Action Command Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/tar'\n"
            "    CommandLine|contains: '--checkpoint-action'\n"
            "  condition: selection"
        ),
        safe_probe_args=["tar", "--version"],
    ),
    BinaryEntry(
        name="find",
        target_os="linux",
        administrative_purpose=(
            "Directory hierarchy search utility used to locate files matching "
            "metadata predicates and perform administrative maintenance."
        ),
        capabilities=("secondary-command-invocation", "suid-privilege-risk"),
        mitre_techniques=("T1083", "T1548.001"),
        risk_weight=7,
        hardening_controls=(
            "Ensure /usr/bin/find never has the SUID or SGID bit set.",
            "Restrict sudoers entries for find by prohibiting -exec, -execdir, and -ok flags via sudo command digests or wrapper scripts.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-exec", "-execdir", "-ok", "-perm -4000"],
        },
        sigma_snippet=(
            "title: Find Utility Spawning Interactive Shell\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/find'\n"
            "    CommandLine|contains: '-exec'\n"
            "  condition: selection"
        ),
        safe_probe_args=["find", "--version"],
    ),
    BinaryEntry(
        name="openssl",
        target_os="linux",
        administrative_purpose=(
            "Cryptography toolkit implementing SSL/TLS protocols, X.509 certificate "
            "operations, digest calculation, and symmetric encryption."
        ),
        capabilities=("tls-network-client", "file-encryption", "shared-engine-loading"),
        mitre_techniques=("T1105", "T1140"),
        risk_weight=7,
        hardening_controls=(
            "Ensure openssl does not hold SUID permissions or elevated file capabilities.",
            "Monitor outbound TLS connections from non-standard parent processes using openssl s_client.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve", "connect"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["s_client", "-engine", "enc -d"],
        },
        sigma_snippet=(
            "title: OpenSSL S_Client or Dynamic Engine Load\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/openssl'\n"
            "    CommandLine|contains:\n"
            "      - 's_client'\n"
            "      - '-engine'\n"
            "  condition: selection"
        ),
        safe_probe_args=["openssl", "version"],
    ),
    BinaryEntry(
        name="curl",
        target_os="linux",
        administrative_purpose=(
            "Command-line tool for transferring data with URLs across HTTP, HTTPS, "
            "SCP, SFTP, and FTP protocols."
        ),
        capabilities=("file-transfer", "http-client"),
        mitre_techniques=("T1105",),
        risk_weight=8,
        hardening_controls=(
            "Remove curl from immutable runtime container images after build stages complete.",
            "Enforce egress proxy allowlists and audit curl invocations writing to /tmp or /dev/shm.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve", "connect"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-o /tmp/", "-O", "--upload-file", "-F", "-d @"],
        },
        sigma_snippet=(
            "title: Curl Download to Temporary Execution Path\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/curl'\n"
            "    CommandLine|contains:\n"
            "      - '/tmp/'\n"
            "      - '/dev/shm/'\n"
            "  condition: selection"
        ),
        safe_probe_args=["curl", "--version"],
    ),
    BinaryEntry(
        name="awk",
        target_os="linux",
        administrative_purpose=(
            "Pattern-scanning and text-processing language used for log parsing, "
            "data extraction, and automated reporting."
        ),
        capabilities=("script-interpreter", "secondary-command-invocation", "suid-privilege-risk"),
        mitre_techniques=("T1059.004", "T1548.001"),
        risk_weight=6,
        hardening_controls=(
            "Verify awk/gawk/mawk binaries do not have SUID/SGID bits enabled.",
            "Avoid granting sudo execution rights to awk without strict argument pinning.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["system(", "/inet/tcp/"],
        },
        sigma_snippet=(
            "title: Awk System Subshell Invocation\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/awk'\n"
            "    CommandLine|contains: 'system('\n"
            "  condition: selection"
        ),
        safe_probe_args=["awk", "--version"],
    ),
    BinaryEntry(
        name="vim",
        target_os="linux",
        administrative_purpose=(
            "Screen-oriented text editor used by system administrators for "
            "interactive configuration editing."
        ),
        capabilities=("interactive-shell-escape", "script-interpreter", "suid-privilege-risk"),
        mitre_techniques=("T1548.001", "T1059.004"),
        risk_weight=7,
        hardening_controls=(
            "Use sudoedit (sudo -e) instead of granting direct sudo access to vim, Always set NOEXEC in sudoers when editors are permitted.",
            "Ensure vim.basic and vim.tiny never carry SUID bits or file capabilities.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-c !", ":!sh", ":py3"],
        },
        sigma_snippet=(
            "title: Vim Non-Interactive Shell Escape Flag\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/vim'\n"
            "    CommandLine|contains: ' -c '\n"
            "  condition: selection"
        ),
        safe_probe_args=["vim", "--version"],
    ),
    BinaryEntry(
        name="perl",
        target_os="linux",
        administrative_purpose=(
            "High-level general-purpose interpreter used across legacy Unix "
            "administration scripts and build toolchains."
        ),
        capabilities=("script-interpreter", "network-socket-client", "suid-privilege-risk"),
        mitre_techniques=("T1059", "T1548.001"),
        risk_weight=8,
        hardening_controls=(
            "Verify /usr/bin/perl has no SUID/SGID bits or cap_setuid file capabilities.",
            "Audit perl -e inline command executions on production servers.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve", "socket", "connect"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-e", "Socket", "exec("],
        },
        sigma_snippet=(
            "title: Perl Inline Script Execution\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/perl'\n"
            "    CommandLine|contains: ' -e '\n"
            "  condition: selection"
        ),
        safe_probe_args=["perl", "--version"],
    ),
    BinaryEntry(
        name="rsync",
        target_os="linux",
        administrative_purpose=(
            "Fast, versatile remote and local file-synchronization utility using "
            "delta-transfer algorithms."
        ),
        capabilities=("file-transfer", "remote-shell-hook", "suid-privilege-risk"),
        mitre_techniques=("T1105", "T1548.001"),
        risk_weight=7,
        hardening_controls=(
            "Restrict rsync under sudo using strict rrsync wrapper scripts and prohibit the -e/--rsh option.",
            "Ensure /usr/bin/rsync does not carry SUID permissions.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-e ", "--rsh="],
        },
        sigma_snippet=(
            "title: Rsync Custom Remote Shell Command Hook\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/rsync'\n"
            "    CommandLine|contains:\n"
            "      - ' -e '\n"
            "      - '--rsh'\n"
            "  condition: selection"
        ),
        safe_probe_args=["rsync", "--version"],
    ),
    BinaryEntry(
        name="busctl",
        target_os="linux",
        administrative_purpose=(
            "Systemd D-Bus introspection and monitoring utility used to inspect "
            "and invoke D-Bus services."
        ),
        capabilities=("ipc-service-invocation", "pager-subshell-hook"),
        mitre_techniques=("T1059.004", "T1548.001"),
        risk_weight=6,
        hardening_controls=(
            "Set SYSTEMD_LESSSECURE=1 in sudoers environment variables when allowing systemd inspection tools.",
            "Audit D-Bus method calls targeting org.freedesktop.systemd1 Manager units.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["call", "org.freedesktop.systemd1"],
        },
        sigma_snippet=(
            "title: Busctl Systemd D-Bus Method Call\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/busctl'\n"
            "    CommandLine|contains: 'call '\n"
            "  condition: selection"
        ),
        safe_probe_args=["busctl", "--version"],
    ),
    BinaryEntry(
        name="env",
        target_os="linux",
        administrative_purpose=(
            "POSIX utility that prints exported environment variables or runs "
            "another program in a modified environment."
        ),
        capabilities=("indirect-command-invocation", "suid-privilege-risk"),
        mitre_techniques=("T1202", "T1548.001"),
        risk_weight=6,
        hardening_controls=(
            "Verify /usr/bin/env never has SUID or SGID mode bits enabled.",
            "Prohibit /usr/bin/env in sudoers rules as it trivially executes arbitrary child binaries.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-S", "-i", "/bin/sh", "/bin/bash"],
        },
        sigma_snippet=(
            "title: Env Utility Spawning Interactive Shell\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/env'\n"
            "    CommandLine|contains:\n"
            "      - '/bin/sh'\n"
            "      - '/bin/bash'\n"
            "  condition: selection"
        ),
        safe_probe_args=["env", "--version"],
    ),
    BinaryEntry(
        name="setarch",
        target_os="linux",
        administrative_purpose=(
            "Utility that modifies reported execution domain and personality flags "
            "(such as ADDR_NO_RANDOMIZE) before executing a target program."
        ),
        capabilities=("indirect-command-invocation", "aslr-modification", "suid-privilege-risk"),
        mitre_techniques=("T1202", "T1548.001"),
        risk_weight=6,
        hardening_controls=(
            "Audit setarch usage with -R (ADDR_NO_RANDOMIZE) which disables ASLR for child processes.",
            "Ensure setarch never holds SUID/SGID bits or sudo privileges.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve", "personality"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-R", "--addr-no-randomize"],
        },
        sigma_snippet=(
            "title: Setarch Disabling Address Space Layout Randomization\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/setarch'\n"
            "    CommandLine|contains:\n"
            "      - ' -R'\n"
            "      - '--addr-no-randomize'\n"
            "  condition: selection"
        ),
        safe_probe_args=["setarch", "--version"],
    ),
    BinaryEntry(
        name="gdb",
        target_os="linux",
        administrative_purpose=(
            "GNU Project Debugger allowing developers to inspect process memory, "
            "attach to running tasks, and evaluate embedded Python expressions."
        ),
        capabilities=("process-memory-inspection", "script-interpreter", "suid-privilege-risk"),
        mitre_techniques=("T1055.008", "T1548.001"),
        risk_weight=9,
        hardening_controls=(
            "Remove gdb from production servers and container images.",
            "Set kernel.yama.ptrace_scope = 2 or 3 via sysctl to restrict ptrace attachment to CAP_SYS_PTRACE.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve", "ptrace"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["-nx", "-ex", "-p ", "attach"],
        },
        sigma_snippet=(
            "title: GDB Batch Command or Process Attachment\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/gdb'\n"
            "    CommandLine|contains:\n"
            "      - '-ex'\n"
            "      - '-p '\n"
            "  condition: selection"
        ),
        safe_probe_args=["gdb", "--version"],
    ),
    BinaryEntry(
        name="capsh",
        target_os="linux",
        administrative_purpose=(
            "Linux capability shell wrapper utility used to test and explore "
            "POSIX capability sets and ambient capability inheritance."
        ),
        capabilities=("capability-manipulation", "indirect-command-invocation", "suid-privilege-risk"),
        mitre_techniques=("T1548.001", "T1059.004"),
        risk_weight=8,
        hardening_controls=(
            "Ensure /sbin/capsh or /usr/sbin/capsh never carries SUID bits or elevated file capabilities.",
            "Restrict access to capsh on multi-tenant production hosts.",
        ),
        expected_telemetry={
            "source": "linux-auditd",
            "syscalls": ["execve", "capset", "prctl"],
            "fields": ["exe", "proctitle", "uid", "euid"],
            "audit_flags": ["--", "--gid=", "--uid=", "--keep="],
        },
        sigma_snippet=(
            "title: Capsh Interactive Shell Wrapper Invocation\n"
            "logsource:\n"
            "  category: process_creation\n"
            "  product: linux\n"
            "detection:\n"
            "  selection:\n"
            "    Image|endswith: '/capsh'\n"
            "    CommandLine|contains: ' --'\n"
            "  condition: selection"
        ),
        safe_probe_args=["capsh", "--print"],
    ),
]


def get_catalog(target_os: Optional[str] = None) -> List[BinaryEntry]:
    """Return catalog entries filtered by target_os ('windows', 'linux', or None/auto for all)."""
    if not target_os or target_os.lower() in ("all", "both"):
        return list(CATALOG)
    normalized = target_os.lower()
    return [entry for entry in CATALOG if entry.target_os == normalized]


def get_entry_by_name(name: str) -> Optional[BinaryEntry]:
    """Look up a single catalog entry by case-insensitive binary name."""
    lower = name.lower()
    for entry in CATALOG:
        if entry.name.lower() == lower:
            return entry
    return None


def filter_by_technique(technique_id: str, target_os: Optional[str] = None) -> List[BinaryEntry]:
    """Return all catalog entries matching a MITRE ATT&CK technique ID prefix (e.g. 'T1218')."""
    prefix = technique_id.upper().strip()
    entries = get_catalog(target_os)
    matched: List[BinaryEntry] = []
    for entry in entries:
        if any(tech.upper() == prefix or tech.upper().startswith(prefix + ".") for tech in entry.mitre_techniques):
            matched.append(entry)
    return matched
