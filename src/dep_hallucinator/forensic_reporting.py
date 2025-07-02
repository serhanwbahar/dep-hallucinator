"""
Forensic reporting for security analysis and historical tracking.

Provides rich console output for forensic analysis results, scan comparisons,
and package timelines.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from rich import box
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

from .forensic_manager import ScanMetadata


class ForensicReporter:
    """Formats and displays forensic analysis results."""

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def print_scan_history(
        self, history: List[ScanMetadata], file_path: Optional[str] = None
    ) -> None:
        """Print scan history in a formatted table."""
        if not history:
            self.console.print("📊 No scan history found", style="yellow")
            return

        title = f"Scan History for {file_path}" if file_path else "Scan History"
        self.console.print(
            f"\n📊 [bold blue]{title}[/bold blue] ({len(history)} scans)"
        )

        # Create table
        table = Table(title=f"📊 {title}", box=box.ROUNDED, title_style="bold cyan")
        table.add_column("Scan ID", style="cyan", min_width=12)
        table.add_column("File", style="blue")
        table.add_column("Timestamp", style="green")
        table.add_column("Dependencies", justify="center")
        table.add_column("Duration", justify="center")
        table.add_column("Options", style="dim")

        for scan in history:
            timestamp = datetime.fromisoformat(
                scan.scan_timestamp.replace("Z", "+00:00")
            )
            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            # Format scan options
            options_str = ""
            if scan.scan_options:
                options = []
                for k, v in scan.scan_options.items():
                    if isinstance(v, bool) and v:
                        options.append(k.replace("_", "-"))
                    elif not isinstance(v, bool):
                        options.append(f"{k.replace('_', '-')}={v}")
                options_str = ", ".join(options)

            table.add_row(
                scan.scan_id[:12] + "...",
                scan.file_path,
                formatted_time,
                str(scan.total_dependencies),
                f"{scan.scan_duration_ms}ms",
                options_str,
            )

        self.console.print(table)

    def print_package_timeline(
        self,
        package_name: str,
        timeline: List[Dict[str, Any]],
        file_path: Optional[str] = None,
    ) -> None:
        """Print package timeline in a visual format."""
        if not timeline:
            self.console.print(
                f"📊 No timeline data found for package: {package_name}", style="yellow"
            )
            return

        title = f"Package Timeline: {package_name}"
        if file_path:
            title += f" (in {file_path})"

        self.console.print(f"\n📈 [bold blue]{title}[/bold blue]")

        # Create timeline tree
        tree = Tree(f"📦 [bold]{package_name}[/bold]")

        for i, entry in enumerate(timeline):
            timestamp = datetime.fromisoformat(
                entry["timestamp"].replace("Z", "+00:00")
            )
            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            # Color code by risk level
            risk_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "green",
            }.get(entry["risk_level"], "white")

            # Create entry text
            entry_text = f"[{risk_color}]{entry['risk_level']}[/{risk_color}]"
            if entry["version"]:
                entry_text += f" │ v{entry['version']}"

            # Add timestamp node
            time_node = tree.add(f"⏰ {formatted_time}")
            status_node = time_node.add(entry_text)

            # Add additional details
            if entry["suspicion_score"]:
                score = int(entry["suspicion_score"] * 100)
                status_node.add(f"🎯 Suspicion Score: {score}%")

            if entry["ml_probability"]:
                ml_score = int(entry["ml_probability"] * 100)
                status_node.add(f"🤖 ML Probability: {ml_score}%")

            if entry["registry_exists"] is not None:
                exists_text = (
                    "✅ Exists in registry"
                    if entry["registry_exists"]
                    else "❌ Not in registry"
                )
                status_node.add(exists_text)

        self.console.print(tree)

    def print_scan_comparison(self, comparison_result: Dict[str, Any]) -> None:
        """Print scan comparison results."""
        if not comparison_result:
            self.console.print("❌ No comparison data available", style="red")
            return

        baseline_id = comparison_result["baseline_scan_id"]
        current_id = comparison_result["current_scan_id"]
        changes = comparison_result["changes"]
        summary = comparison_result["summary"]
        risk_trend = comparison_result["risk_trend"]

        # Print header
        self.console.print("\n🔬 [bold blue]Scan Comparison[/bold blue]")
        self.console.print(f"   Baseline: [cyan]{baseline_id[:12]}...[/cyan]")
        self.console.print(f"   Current:  [cyan]{current_id[:12]}...[/cyan]")

        # Print risk trend
        trend_color = {"IMPROVED": "green", "DEGRADED": "red", "STABLE": "blue"}.get(
            risk_trend, "white"
        )

        trend_icon = {"IMPROVED": "📈", "DEGRADED": "📉", "STABLE": "📊"}.get(
            risk_trend, "📊"
        )

        self.console.print(
            f"   Trend:    [{trend_color}]{trend_icon} {risk_trend}[/{trend_color}]"
        )

        if not changes:
            self.console.print("\n✅ No changes detected between scans", style="green")
            return

        # Print summary
        self.console.print(f"\n📊 [bold]Change Summary[/bold] ({len(changes)} changes)")

        change_counts = {}
        for change in changes:
            change_type = change["change_type"]
            change_counts[change_type] = change_counts.get(change_type, 0) + 1

        for change_type, count in change_counts.items():
            icon = self._get_change_icon(change_type)
            color = self._get_change_color(change_type)
            formatted_type = change_type.replace("_", " ").title()
            self.console.print(
                f"   {icon} [{color}]{formatted_type}[/{color}]: {count}"
            )

        # Print detailed changes
        self.console.print("\n📋 [bold]Detailed Changes[/bold]")

        # Group changes by type
        changes_by_type = {}
        for change in changes:
            change_type = change["change_type"]
            if change_type not in changes_by_type:
                changes_by_type[change_type] = []
            changes_by_type[change_type].append(change)

        for change_type, type_changes in changes_by_type.items():
            icon = self._get_change_icon(change_type)
            color = self._get_change_color(change_type)
            formatted_type = change_type.replace("_", " ").title()

            self.console.print(f"\n{icon} [{color}]{formatted_type}[/{color}]:")

            for change in type_changes:
                self.console.print(f"   📦 {change['package_name']}")
                if change.get("description"):
                    self.console.print(f"      💭 {change['description']}", style="dim")

    def _get_change_icon(self, change_type: str) -> str:
        """Get icon for change type."""
        icons = {
            "package_added": "📥",
            "package_removed": "📤",
            "risk_increased": "⬆️",
            "risk_decreased": "⬇️",
            "version_changed": "🔄",
            "new_vulnerability": "🚨",
            "resolved_vulnerability": "✅",
        }
        return icons.get(change_type, "🔄")

    def _get_change_color(self, change_type: str) -> str:
        """Get color for change type."""
        colors = {
            "package_added": "blue",
            "package_removed": "yellow",
            "risk_increased": "red",
            "risk_decreased": "green",
            "version_changed": "blue",
            "new_vulnerability": "red",
            "resolved_vulnerability": "green",
        }
        return colors.get(change_type, "white")

    def print_forensic_summary(self, stats: Dict[str, Any]) -> None:
        """Print forensic database summary statistics."""
        self.console.print("\n📊 [bold blue]Forensic Database Summary[/bold blue]")

        if not stats:
            self.console.print("   No data available", style="dim")
            return

        # Create summary table
        table = Table(
            title="📊 Database Statistics", box=box.ROUNDED, title_style="bold cyan"
        )
        table.add_column("Metric", style="bold")
        table.add_column("Value", justify="center")
        table.add_column("Description", style="dim")

        table.add_row(
            "Total Scans",
            str(stats.get("total_scans", 0)),
            "Number of stored scan results",
        )

        table.add_row(
            "Unique Files",
            str(stats.get("unique_files", 0)),
            "Number of different dependency files scanned",
        )

        table.add_row(
            "Total Findings",
            str(stats.get("total_findings", 0)),
            "Number of security findings across all scans",
        )

        table.add_row(
            "Database Size",
            f"{stats.get('db_size_mb', 0):.1f} MB",
            "Size of forensic database file",
        )

        if "oldest_scan" in stats:
            oldest = datetime.fromisoformat(stats["oldest_scan"].replace("Z", "+00:00"))
            table.add_row(
                "Oldest Scan",
                oldest.strftime("%Y-%m-%d"),
                "Date of oldest scan in database",
            )

        if "latest_scan" in stats:
            latest = datetime.fromisoformat(stats["latest_scan"].replace("Z", "+00:00"))
            table.add_row(
                "Latest Scan", latest.strftime("%Y-%m-%d"), "Date of most recent scan"
            )

        self.console.print(table)


def create_forensic_progress(description: str) -> Progress:
    """Create a progress indicator for forensic operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=Console(),
        transient=True,
    )
