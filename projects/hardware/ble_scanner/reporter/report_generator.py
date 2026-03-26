"""
Report Generator
----------------
Generates JSON files and formatted terminal output for
scan results and security assessments.
"""

from __future__ import annotations

import json
import os
from typing import Any

from models import BLEDevice, AssessmentReport, DeviceProfile, SecurityFinding


class ReportGenerator:
    """Generate reports in various formats."""

    def __init__(self, output_dir: str = "."):
        self.output_dir = output_dir
        os.makedirs(output_dir, exist_ok=True)

    def generate_json(
        self,
        report: AssessmentReport,
        filename: str = "phantom_report.json",
    ) -> str:
        """Write assessment report as JSON.

        Returns:
            Path to the written file.
        """
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            json.dump(report.to_dict(), f, indent=2, default=str)
        return path

    def generate_scan_json(
        self,
        devices: list[BLEDevice],
        filename: str = "phantom_scan.json",
    ) -> str:
        """Write scan results as JSON.

        Returns:
            Path to the written file.
        """
        path = os.path.join(self.output_dir, filename)
        data = {
            "devices": [d.to_dict() for d in devices],
            "total": len(devices),
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2, default=str)
        return path

    def generate_jsonl(
        self,
        findings: list[SecurityFinding],
        filename: str = "phantom_findings.jsonl",
    ) -> str:
        """Write findings as JSON Lines (one finding per line).

        Returns:
            Path to the written file.
        """
        path = os.path.join(self.output_dir, filename)
        with open(path, "w") as f:
            for finding in findings:
                f.write(json.dumps(finding.to_dict(), default=str) + "\n")
        return path

    @staticmethod
    def format_scan_table(
        devices: list[BLEDevice],
        config: Any = None,
    ) -> str:
        """Format scan results as a terminal table.

        Returns:
            Formatted string ready for printing.
        """
        if not devices:
            return "  No devices found."

        lines: list[str] = []
        header = f"  {'ADDR':<20} {'NAME':<24} {'RSSI':>5}  {'TYPE':<8} {'MANUFACTURER':<20} {'SERVICES'}"
        lines.append(header)
        lines.append("  " + "-" * (len(header) - 2))

        for dev in devices:
            name = dev.name or "[Unknown]"
            if len(name) > 22:
                name = name[:19] + "..."

            # Resolve manufacturer from first company ID
            mfr = "—"
            if dev.manufacturer_data and config:
                first_id = next(iter(dev.manufacturer_data))
                mfr = config.company_ids.get(first_id, f"0x{first_id:04X}")
            if len(mfr) > 18:
                mfr = mfr[:15] + "..."

            # Resolve service names
            svc_names: list[str] = []
            if config:
                for uuid in dev.service_uuids[:3]:
                    resolved = config.standard_services.get(uuid.lower(), "")
                    svc_names.append(resolved or uuid[:8])
            else:
                svc_names = [u[:8] for u in dev.service_uuids[:3]]
            svcs = ", ".join(svc_names) if svc_names else "—"

            lines.append(
                f"  {dev.address:<20} {name:<24} {dev.rssi:>5}  "
                f"{dev.address_type:<8} {mfr:<20} {svcs}"
            )

        return "\n".join(lines)

    @staticmethod
    def format_enumeration_tree(profile: DeviceProfile) -> str:
        """Format GATT enumeration as a tree view.

        Returns:
            Formatted string ready for printing.
        """
        lines: list[str] = []
        dev = profile.device
        lines.append(f"  Device: {dev.name or '[Unknown]'} ({dev.address})")
        lines.append(f"  Status: {'Connected' if profile.connection_successful else 'Failed'}")
        if profile.error:
            lines.append(f"  Error:  {profile.error}")
        lines.append("")

        for i, svc in enumerate(profile.services):
            prefix = "└── " if i == len(profile.services) - 1 else "├── "
            lines.append(f"  {prefix}Service: {svc.description} [{svc.uuid}]")

            for j, char in enumerate(svc.characteristics):
                is_last_svc = i == len(profile.services) - 1
                branch = "    " if is_last_svc else "│   "
                char_prefix = "└── " if j == len(svc.characteristics) - 1 else "├── "

                props_str = ", ".join(char.properties)
                lines.append(f"  {branch}{char_prefix}Char: {char.uuid}")
                lines.append(f"  {branch}{'    ' if j == len(svc.characteristics) - 1 else '│   '}Properties: {props_str}")

                if char.value_decoded is not None:
                    val_preview = char.value_decoded[:60]
                    lines.append(f"  {branch}{'    ' if j == len(svc.characteristics) - 1 else '│   '}Value: {val_preview}")

                for k, desc in enumerate(char.descriptors):
                    desc_branch = "    " if j == len(svc.characteristics) - 1 else "│   "
                    desc_prefix = "└── " if k == len(char.descriptors) - 1 else "├── "
                    lines.append(f"  {branch}{desc_branch}{desc_prefix}Desc: {desc.uuid}")

        return "\n".join(lines)

    @staticmethod
    def format_assessment_summary(
        report: AssessmentReport,
        c_func: Any = None,
    ) -> str:
        """Format assessment findings as a terminal summary.

        Args:
            report: The assessment report.
            c_func: Optional color function (ignored if None).

        Returns:
            Formatted string ready for printing.
        """
        lines: list[str] = []
        dev = report.target

        # Risk score label
        if report.risk_score >= 7:
            risk_label = "HIGH"
        elif report.risk_score >= 4:
            risk_label = "MEDIUM"
        else:
            risk_label = "LOW"

        lines.append(f"  Target: {dev.name or '[Unknown]'} ({dev.address})")
        lines.append(f"  Risk Score: {report.risk_score:.1f}/10 ({risk_label})")
        lines.append("")

        if not report.findings:
            lines.append("  No security findings.")
            return "\n".join(lines)

        lines.append("  FINDINGS:")

        sev_markers = {
            "critical": "[!!]",
            "high": "[!] ",
            "medium": "[*] ",
            "low": "[.] ",
            "info": "[i] ",
        }

        for finding in sorted(report.findings, key=lambda f: {
            "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
        }.get(f.severity, 5)):
            marker = sev_markers.get(finding.severity, "[?] ")
            lines.append(
                f"  {marker} {finding.severity.upper():<8} {finding.finding_id:<14} {finding.title}"
            )
            lines.append(f"           {finding.description[:80]}")

        return "\n".join(lines)
