"""
Reporting and output formatting for security scan results.

Provides color-coded console output using Rich library.
"""

from typing import List, Optional

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
)
from rich.table import Table

from .scanner import RiskLevel, ScanResult, SecurityFinding


class SecurityReporter:
    """Formats and displays security scan results."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_scan_results(self, scan_result: ScanResult, file_path: str) -> None:
        """
        Print scan results in a user-friendly format.

        Args:
            scan_result: The scan results to display
            file_path: Path to the scanned file
        """
        self.console.print()
        self._print_header(file_path, scan_result)

        if scan_result.errors:
            self._print_errors(scan_result.errors)

        if scan_result.findings:
            self._print_summary(scan_result)
            self._print_findings(scan_result.findings)
            self._print_recommendations(scan_result)
        else:
            self.console.print("✅ No dependencies found to scan.", style="green")

        self._print_footer(scan_result)

    def _print_header(self, file_path: str, scan_result: ScanResult) -> None:
        """Print scan header with file info."""
        header_text = f"🔍 Security Scan Results: {file_path}"
        self.console.print(
            Panel(
                header_text,
                title="[bold blue]Dep-Hallucinator Security Scanner[/bold blue]",
                border_style="blue",
            )
        )

    def _print_summary(self, scan_result: ScanResult) -> None:
        """Print a summary of findings by risk level."""
        critical_count = len(scan_result.critical_findings)
        high_count = len(scan_result.high_risk_findings)

        table = Table(title="📊 Scan Summary", box=box.ROUNDED, title_style="bold cyan")
        table.add_column("Risk Level", style="bold")
        table.add_column("Count", justify="center")
        table.add_column("Status", justify="center")

        # Add critical findings
        if critical_count > 0:
            table.add_row(
                "🚨 CRITICAL",
                f"[bold red]{critical_count}[/bold red]",
                "[bold red]VULNERABLE[/bold red]",
            )

        # Add high risk findings
        if high_count > 0:
            table.add_row(
                "⚠️  HIGH",
                f"[bold yellow]{high_count}[/bold yellow]",
                "[bold yellow]SUSPICIOUS[/bold yellow]",
            )

        # Add other counts
        medium_count = len(
            [f for f in scan_result.findings if f.risk_level == RiskLevel.MEDIUM]
        )
        low_count = len(
            [f for f in scan_result.findings if f.risk_level == RiskLevel.LOW]
        )
        error_count = len(
            [f for f in scan_result.findings if f.risk_level == RiskLevel.ERROR]
        )

        if medium_count > 0:
            table.add_row("⚡ MEDIUM", str(medium_count), "[yellow]REVIEW[/yellow]")
        if low_count > 0:
            table.add_row("✅ LOW", str(low_count), "[green]OK[/green]")
        if error_count > 0:
            table.add_row("❌ ERROR", str(error_count), "[red]FAILED[/red]")

        self.console.print(table)
        self.console.print()

    def _print_findings(self, findings: List[SecurityFinding]) -> None:
        """Print detailed findings grouped by risk level."""
        # Group findings by risk level
        critical_findings = [f for f in findings if f.risk_level == RiskLevel.CRITICAL]
        high_findings = [f for f in findings if f.risk_level == RiskLevel.HIGH]
        other_findings = [
            f
            for f in findings
            if f.risk_level not in [RiskLevel.CRITICAL, RiskLevel.HIGH]
        ]

        # Print critical findings first (most important)
        if critical_findings:
            self._print_critical_findings(critical_findings)

        # Print high risk findings
        if high_findings:
            self._print_high_risk_findings(high_findings)

        # Print other findings in a condensed format
        if other_findings:
            self._print_other_findings(other_findings)

    def _print_critical_findings(self, findings: List[SecurityFinding]) -> None:
        """Print critical findings with detailed information."""
        self.console.print(
            Panel(
                "🚨 CRITICAL VULNERABILITIES - IMMEDIATE ACTION REQUIRED",
                style="bold red",
                border_style="red",
            )
        )

        for finding in findings:
            self._print_detailed_finding(finding, "red")

    def _print_high_risk_findings(self, findings: List[SecurityFinding]) -> None:
        """Print high risk findings with detailed information."""
        self.console.print(
            Panel(
                "⚠️  HIGH RISK PACKAGES - REVIEW REQUIRED",
                style="bold yellow",
                border_style="yellow",
            )
        )

        for finding in findings:
            self._print_detailed_finding(finding, "yellow")

    def _print_detailed_finding(self, finding: SecurityFinding, color: str) -> None:
        """Print a detailed finding with reasons and recommendations."""
        # Package header
        package_header = f"📦 {finding.dependency.name}"
        if finding.dependency.version != "any":
            package_header += f" ({finding.dependency.version})"

        self.console.print(f"\n[bold {color}]{package_header}[/bold {color}]")

        # Print heuristic score if available
        if finding.heuristic_score and finding.heuristic_score.overall_score > 0:
            score_percent = int(finding.heuristic_score.overall_score * 100)
            score_display = f"   [bold]Suspicion Score:[/bold] {score_percent}% ({finding.heuristic_score.risk_level})"

            # Add ML indicator if ML analysis was performed
            if finding.heuristic_score.ml_analysis:
                ml_percent = int(
                    finding.heuristic_score.ml_analysis.overall_ai_probability * 100
                )
                score_display += f" | ML: {ml_percent}%"

            self.console.print(score_display)

        # Print reasons
        if finding.reasons:
            self.console.print("   [bold]Reasons:[/bold]")
            for reason in finding.reasons:
                self.console.print(f"   • {reason}", style=color)

        # Print heuristic details for high-risk findings
        if finding.heuristic_score and finding.risk_level in ["HIGH", "MEDIUM"]:
            self._print_heuristic_details(finding.heuristic_score, color)

        # Print recommendations
        if finding.recommendations:
            self.console.print("   [bold]Recommendations:[/bold]")
            for rec in finding.recommendations:
                self.console.print(f"   → {rec}", style=f"bold {color}")

        # Print registry info if available
        if finding.registry_result and finding.registry_result.check_duration_ms:
            duration = finding.registry_result.check_duration_ms
            registry = finding.registry_result.registry_type.upper()
            self.console.print(f"   [dim]Checked {registry} in {duration}ms[/dim]")

    def _print_heuristic_details(self, heuristic_score, color: str) -> None:
        """Print detailed heuristic analysis results."""
        self.console.print("   [bold]Heuristic Analysis:[/bold]")

        for result in heuristic_score.heuristic_results:
            if result.score > 0.3:  # Only show significant heuristic findings
                heuristic_name = result.heuristic_type.value.replace("_", " ").title()
                score_percent = int(result.score * 100)
                confidence_percent = int(result.confidence * 100)

                self.console.print(
                    f"     • {heuristic_name}: {score_percent}% "
                    f"(confidence: {confidence_percent}%)",
                    style=f"dim {color}",
                )

                # Show the most important reason for this heuristic
                if result.reasons:
                    main_reason = result.reasons[0]
                    self.console.print(f"       └─ {main_reason}", style=f"dim {color}")

        # Show ML analysis details if available
        if (
            heuristic_score.ml_analysis
            and heuristic_score.ml_analysis.overall_ai_probability > 0.3
        ):
            self._print_ml_analysis_details(heuristic_score.ml_analysis, color)

    def _print_ml_analysis_details(self, ml_analysis, color: str) -> None:
        """Print detailed ML analysis results."""
        self.console.print("   [bold]ML Pattern Analysis:[/bold]")

        ai_prob_percent = int(ml_analysis.overall_ai_probability * 100)
        self.console.print(
            f"     • Overall AI Probability: {ai_prob_percent}% "
            f"(confidence: {ml_analysis.confidence_level})",
            style=f"dim {color}",
        )

        # Show individual model predictions
        for prediction in ml_analysis.model_predictions:
            if prediction.probability > 0.3:
                model_name = prediction.model_type.value.replace("_", " ").title()
                prob_percent = int(prediction.probability * 100)
                conf_percent = int(prediction.confidence * 100)

                self.console.print(
                    f"     • {model_name}: {prob_percent}% (confidence: {conf_percent}%)",
                    style=f"dim {color}",
                )

                # Show detected features for this model
                if prediction.features_detected:
                    features_str = ", ".join(prediction.features_detected[:2])
                    if len(prediction.features_detected) > 2:
                        features_str += (
                            f" (+{len(prediction.features_detected) - 2} more)"
                        )
                    self.console.print(
                        f"       └─ Features: {features_str}", style=f"dim {color}"
                    )

    def _print_other_findings(self, findings: List[SecurityFinding]) -> None:
        """Print other findings in a condensed table format."""
        if not findings:
            return

        table = Table(title="📋 Other Findings", box=box.SIMPLE, title_style="bold")
        table.add_column("Package", style="bold")
        table.add_column("Risk Level", justify="center")
        table.add_column("Status", justify="center")

        for finding in findings:
            risk_color = {
                RiskLevel.MEDIUM: "yellow",
                RiskLevel.LOW: "green",
                RiskLevel.ERROR: "red",
            }.get(finding.risk_level, "white")

            status = {
                RiskLevel.MEDIUM: "Review Required",
                RiskLevel.LOW: "Legitimate",
                RiskLevel.ERROR: "Check Failed",
            }.get(finding.risk_level, "Unknown")

            table.add_row(
                finding.dependency.name,
                f"[{risk_color}]{finding.risk_level.value}[/{risk_color}]",
                f"[{risk_color}]{status}[/{risk_color}]",
            )

        self.console.print(table)
        self.console.print()

    def _print_recommendations(self, scan_result: ScanResult) -> None:
        """Print overall recommendations based on scan results."""
        if scan_result.has_critical_vulnerabilities:
            self.console.print(
                Panel(
                    "⚠️  [bold red]CRITICAL SECURITY RISK DETECTED[/bold red]\n\n"
                    "• Do NOT install the packages marked as CRITICAL\n"
                    "• These packages do not exist and can be exploited\n"
                    "• Review your dependency sources carefully\n"
                    "• Consider if these were suggested by an AI assistant",
                    title="[bold red]⚠️  SECURITY ALERT[/bold red]",
                    border_style="red",
                )
            )
        else:
            self.console.print(
                Panel(
                    "✅ No critical vulnerabilities detected.\n"
                    "All packages appear to exist in their respective registries.",
                    title="[bold green]✅ Security Status[/bold green]",
                    border_style="green",
                )
            )

    def _print_errors(self, errors: List[str]) -> None:
        """Print scan errors."""
        if not errors:
            return

        error_text = "\n".join(f"• {error}" for error in errors)
        self.console.print(
            Panel(
                error_text,
                title="[bold red]⚠️  Scan Errors[/bold red]",
                border_style="red",
            )
        )
        self.console.print()

    def _print_footer(self, scan_result: ScanResult) -> None:
        """Print scan footer with timing and summary."""
        duration_seconds = scan_result.scan_duration_ms / 1000

        footer_text = (
            f"Scanned {scan_result.total_dependencies} dependencies "
            f"in {duration_seconds:.2f} seconds"
        )

        self.console.print(f"\n[dim]{footer_text}[/dim]")

        # Print final security verdict
        if scan_result.has_critical_vulnerabilities:
            self.console.print(
                "\n[bold red]🚨 SECURITY SCAN FAILED - Critical vulnerabilities found![/bold red]"
            )
        else:
            self.console.print(
                "\n[bold green]✅ SECURITY SCAN PASSED - No critical vulnerabilities detected.[/bold green]"
            )


def create_progress_spinner(description: str) -> Progress:
    """Create a progress spinner for long-running operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=Console(),
    )
