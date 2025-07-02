import asyncio
import json
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console
from rich.panel import Panel

from .cache_manager import get_cache_manager
from .cli_config import (
    create_sample_config,
    get_config,
    load_config,
    load_config_file,
)
from .completion import get_completion_scripts
from .dependency import Dependency
from .forensic_manager import get_forensic_manager
from .package_lists import MatchType, get_package_list_manager
from .parsers import parse_dependency_file as parse_deps
from .performance_optimizer import apply_production_optimizations, get_performance_stats
from .reporting import SecurityReporter
from .sbom_generator import SBOMFormat, generate_sbom_from_scan
from .scanner import RiskLevel, get_dependency_scanner
from .structured_logging import (
    clear_scan_context,
    log_scan_complete,
    log_scan_start,
    set_scan_context,
)

__version__ = "1.0.0"

console = Console()


def parse_dependency_file(file_path: str) -> List[Dependency]:
    """Parse dependency file using the comprehensive parser."""
    try:
        # Use the comprehensive parser from parsers.py
        raw_deps = parse_deps(file_path)

        dependencies = []
        for dep in raw_deps:
            dependencies.append(
                Dependency(
                    name=dep["name"], version=dep["version"], source_file=dep["source"]
                )
            )

        return dependencies
    except ValueError as e:
        raise click.ClickException(f"Failed to parse dependency file: {str(e)}")
    except Exception as e:
        raise click.ClickException(f"Unexpected error parsing file: {str(e)}")


def output_json_results(
    scan_result, file_path: str, output_file: Optional[str] = None
) -> None:
    """Export results as JSON."""
    results = {
        "file_path": file_path,
        "total_dependencies": scan_result.total_dependencies,
        "scan_duration_ms": scan_result.scan_duration_ms,
        "summary": {
            "critical": len(scan_result.critical_findings),
            "high": len(
                [f for f in scan_result.findings if f.risk_level == RiskLevel.HIGH]
            ),
            "medium": len(
                [f for f in scan_result.findings if f.risk_level == RiskLevel.MEDIUM]
            ),
            "low": len(
                [f for f in scan_result.findings if f.risk_level == RiskLevel.LOW]
            ),
            "errors": len(
                [f for f in scan_result.findings if f.risk_level == RiskLevel.ERROR]
            ),
        },
        "has_vulnerabilities": scan_result.has_critical_vulnerabilities,
        "findings": [],
    }

    for finding in scan_result.findings:
        finding_data = {
            "package": finding.dependency.name,
            "version": finding.dependency.version,
            "risk_level": finding.risk_level.value,
            "reasons": finding.reasons or [],
            "recommendations": finding.recommendations or [],
        }

        if finding.heuristic_score:
            finding_data["heuristic_score"] = {
                "overall_score": finding.heuristic_score.overall_score,
                "risk_level": finding.heuristic_score.risk_level,
                "ml_probability": (
                    finding.heuristic_score.ml_analysis.overall_ai_probability
                    if finding.heuristic_score.ml_analysis
                    else 0.0
                ),
            }

        results["findings"].append(finding_data)

    if scan_result.errors:
        results["scan_errors"] = scan_result.errors

    json_output = json.dumps(results, indent=2, ensure_ascii=False)

    if output_file:
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(json_output)
        console.print(f"✅ Results saved to {output_file}", style="green")
    else:
        print(json_output)


async def async_scan_dependencies(
    file_path: str,
    rate_limit: float,
    max_concurrent: int,
    output_format: str,
    output_file: Optional[str],
    verbose: bool,
    quiet: bool,
    resolve_transitive: bool = False,
    max_depth: int = 3,
    verify_signatures: bool = False,
    generate_sbom: bool = False,
    sbom_format: str = "spdx",
    sbom_output: Optional[str] = None,
) -> None:
    """Run security scan."""
    reporter = SecurityReporter()

    try:
        if verbose and not quiet:
            console.print(f"📁 Parsing file: {file_path}", style="blue")

        dependencies = parse_dependency_file(file_path)

        if not dependencies:
            if not quiet:
                console.print("ℹ️  No dependencies found in the file.", style="yellow")
            return

        scan_id = f"scan_{int(time.time())}"
        set_scan_context(
            scan_id=scan_id, file_path=file_path, total_dependencies=len(dependencies)
        )

        # Log scan start
        log_scan_start(scan_id, file_path, len(dependencies))

        if not quiet:
            console.print(
                f"🔍 Scanning {len(dependencies)} dependencies...", style="blue"
            )
            if verbose:
                console.print(
                    f"⚙️  Rate limit: {rate_limit} req/s, Max concurrent: {max_concurrent}",
                    style="dim",
                )

        scanner = get_dependency_scanner(
            rate_limit_rps=rate_limit,
            max_concurrent=max_concurrent,
            resolve_transitive=resolve_transitive,
            max_depth=max_depth,
            verify_signatures=verify_signatures,
        )

        if resolve_transitive:
            scan_result = await scanner.scan_dependency_file(file_path)
        else:
            scan_result = await scanner.scan_dependencies(dependencies)

        if output_format == "json":
            output_json_results(scan_result, file_path, output_file)
        else:
            if not quiet:
                reporter.print_scan_results(scan_result, file_path)
            elif scan_result.has_critical_vulnerabilities:
                console.print(
                    f"❌ CRITICAL: {len(scan_result.critical_findings)} vulnerable dependencies found in {file_path}",
                    style="red",
                )

        if generate_sbom:
            if not sbom_output:
                # Generate default SBOM output path
                source_path = Path(file_path)
                sbom_output = str(
                    source_path.parent
                    / f"{source_path.stem}-sbom.{sbom_format.lower()}.json"
                )

            try:
                if not quiet:
                    console.print(
                        f"📋 Generating {sbom_format.upper()} SBOM...", style="blue"
                    )

                sbom_format_enum = (
                    SBOMFormat.SPDX
                    if sbom_format.lower() == "spdx"
                    else SBOMFormat.CYCLONEDX
                )
                generate_sbom_from_scan(
                    scan_result, file_path, sbom_output, sbom_format_enum
                )

                if not quiet:
                    console.print(f"✅ SBOM saved to {sbom_output}", style="green")

            except Exception as e:
                console.print(f"❌ Failed to generate SBOM: {str(e)}", style="red")
                if verbose:
                    raise

        # Log scan completion
        critical_count = len(scan_result.critical_findings)
        high_count = len(scan_result.high_risk_findings)
        log_scan_complete(
            scan_id,
            scan_result.scan_duration_ms,
            len(scan_result.findings),
            critical_count,
            high_count,
        )

        # Store scan results for forensic analysis
        if not quiet:
            try:
                forensic_manager = get_forensic_manager()
                forensic_scan_id = forensic_manager.store_scan(
                    scan_result,
                    file_path,
                    {
                        "rate_limit": rate_limit,
                        "max_concurrent": max_concurrent,
                        "resolve_transitive": resolve_transitive,
                        "verify_signatures": verify_signatures,
                    },
                )
                if verbose:
                    console.print(
                        f"📊 Scan stored for forensic analysis: {forensic_scan_id[:8]}...",
                        style="dim",
                    )
            except Exception as e:
                if verbose:
                    console.print(
                        f"⚠️  Could not store forensic data: {str(e)}", style="yellow"
                    )

        # Clear scan context
        clear_scan_context()

        if scan_result.has_critical_vulnerabilities:
            sys.exit(1)

    except Exception as e:
        if verbose:
            raise click.ClickException(f"Error during security scan: {str(e)}")
        else:
            raise click.ClickException(f"Scan failed: {str(e)}")


async def _initialize_production_optimizations():
    """Initialize production optimizations if enabled."""
    try:
        config = get_config()
        if config.production.enable_metrics or hasattr(config.production, 'enable_uvloop') and config.production.enable_uvloop:
            optimization_results = await apply_production_optimizations()
            if config.logging.log_level == "DEBUG":
                console.print(f"🚀 Production optimizations applied: {optimization_results}", style="dim")
    except Exception as e:
        # Don't fail startup if optimizations fail
        if get_config().logging.log_level == "DEBUG":
            console.print(f"⚠️  Production optimization failed: {e}", style="yellow")


@click.group(invoke_without_command=True)
@click.option("--version", is_flag=True, help="Show version information")
@click.option("--performance-stats", is_flag=True, help="Show performance statistics")
@click.pass_context
def cli(ctx, version, performance_stats):
    """
    🔍 Dep-Hallucinator: AI-Generated Dependency Confusion Scanner

    Detects potentially hallucinated packages that could be exploited
    in dependency confusion attacks.
    """
    if version:
        console.print(f"Dep-Hallucinator version {__version__}", style="bold blue")
        ctx.exit()

    if performance_stats:
        stats = get_performance_stats()
        console.print("📊 Performance Statistics:")
        console.print_json(data=stats)
        ctx.exit()

    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
    else:
        try:
            try:
                loop = asyncio.get_running_loop()
                asyncio.create_task(_initialize_production_optimizations())
            except RuntimeError:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(_initialize_production_optimizations())
                loop.close()
        except Exception:
            pass


@cli.command()
@click.argument(
    "file_path", type=click.Path(exists=True, readable=True, dir_okay=False)
)
@click.option(
    "--rate-limit",
    type=float,
    help="API requests per second limit (default from config or 10.0)",
)
@click.option(
    "--max-concurrent",
    type=int,
    help="Maximum concurrent registry checks (default from config or 20)",
)
@click.option(
    "--output-format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format for results",
    show_default=True,
)
@click.option(
    "--output-file",
    "-o",
    type=click.Path(),
    help="Save results to file (JSON format only)",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-critical output")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output with additional details",
)
@click.option(
    "--fail-on-high",
    is_flag=True,
    help="Exit with error code if HIGH risk packages are found (in addition to CRITICAL)",
)
@click.option(
    "--resolve-transitive",
    is_flag=True,
    help="Resolve and scan transitive dependencies (dependencies of dependencies)",
)
@click.option(
    "--max-depth",
    type=int,
    default=3,
    help="Maximum depth for transitive dependency resolution (default: 3)",
    show_default=True,
)
@click.option(
    "--verify-signatures",
    is_flag=True,
    help="Verify package signatures using 2025 standards (PyPI attestations, npm provenance)",
)
@click.option(
    "--generate-sbom",
    is_flag=True,
    help="Generate Software Bill of Materials (SBOM) from scan results",
)
@click.option(
    "--sbom-format",
    type=click.Choice(["spdx", "cyclonedx"], case_sensitive=False),
    default="spdx",
    help="SBOM output format (default: spdx)",
    show_default=True,
)
@click.option(
    "--sbom-output",
    type=click.Path(),
    help="Output file path for SBOM (default: <source-file>-sbom.<format>.json)",
)
def scan(
    file_path: str,
    rate_limit: Optional[float],
    max_concurrent: Optional[int],
    output_format: str,
    output_file: Optional[str],
    quiet: bool,
    verbose: bool,
    fail_on_high: bool,
    resolve_transitive: bool,
    max_depth: int,
    verify_signatures: bool,
    generate_sbom: bool,
    sbom_format: str,
    sbom_output: Optional[str],
) -> None:
    """
    Scan a dependency file for AI-generated packages and security vulnerabilities.

    Examples:

      dep-hallucinator scan requirements.txt

      dep-hallucinator scan requirements.txt --rate-limit 5 --max-concurrent 10

      dep-hallucinator scan requirements.txt --output-format json -o results.json

      dep-hallucinator scan requirements.txt --quiet
    """
    try:
        config = load_config()

        final_rate_limit = (
            rate_limit if rate_limit is not None else config.scan.rate_limit
        )
        final_max_concurrent = (
            max_concurrent if max_concurrent is not None else config.scan.max_concurrent
        )
        final_fail_on_high = fail_on_high or config.scan.fail_on_high

        if final_rate_limit <= 0:
            raise click.ClickException("Rate limit must be positive")
        if final_max_concurrent <= 0:
            raise click.ClickException("Max concurrent must be positive")
        if output_file and output_format != "json":
            raise click.ClickException("Output file can only be used with JSON format")

        if not quiet:
            console.print(
                Panel(
                    f"🔍 [bold blue]Dep-Hallucinator Security Scanner[/bold blue] v{__version__}",
                    border_style="blue",
                )
            )

        asyncio.run(
            async_scan_dependencies(
                file_path,
                final_rate_limit,
                final_max_concurrent,
                output_format,
                output_file,
                verbose,
                quiet,
                resolve_transitive,
                max_depth,
                verify_signatures,
                generate_sbom,
                sbom_format,
                sbom_output,
            )
        )

    except KeyboardInterrupt:
        Console(stderr=True).print("\n⚠️  Scan interrupted by user", style="yellow")
        sys.exit(130)
    except Exception as e:
        if not quiet:
            Console(stderr=True).print(f"❌ Error: {str(e)}", style="red")
        sys.exit(1)


@cli.command()
@click.argument(
    "files",
    nargs=-1,
    type=click.Path(exists=True, readable=True, dir_okay=False),
    required=True,
)
@click.option(
    "--rate-limit",
    default=10.0,
    type=float,
    help="API requests per second limit (default: 10.0)",
    show_default=True,
)
@click.option(
    "--max-concurrent",
    default=20,
    type=int,
    help="Maximum concurrent registry checks (default: 20)",
    show_default=True,
)
@click.option(
    "--output-format",
    type=click.Choice(["console", "json"], case_sensitive=False),
    default="console",
    help="Output format for results",
    show_default=True,
)
@click.option(
    "--output-dir",
    type=click.Path(file_okay=False, writable=True),
    help="Directory to save individual result files (JSON format only)",
)
@click.option("--quiet", "-q", is_flag=True, help="Suppress non-critical output")
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose output with additional details",
)
def batch(
    files: tuple,
    rate_limit: float,
    max_concurrent: int,
    output_format: str,
    output_dir: Optional[str],
    quiet: bool,
    verbose: bool,
) -> None:
    """
    Scan multiple dependency files in batch mode.

    Examples:

      dep-hallucinator batch requirements.txt package.json

      dep-hallucinator batch *.txt --output-format json --output-dir results/
    """
    if not files:
        raise click.ClickException("At least one file must be specified")

    if output_dir:
        Path(output_dir).mkdir(parents=True, exist_ok=True)

    total_vulnerabilities = 0
    failed_scans = 0

    if not quiet:
        console.print(f"🔍 Starting batch scan of {len(files)} files...", style="blue")

    for file_path in files:
        try:
            if not quiet:
                console.print(f"\n📁 Scanning: {file_path}", style="cyan")

            output_file = None
            if output_dir and output_format == "json":
                file_stem = Path(file_path).stem
                output_file = Path(output_dir) / f"{file_stem}_results.json"

            try:
                asyncio.run(
                    async_scan_dependencies(
                        file_path,
                        rate_limit,
                        max_concurrent,
                        output_format,
                        str(output_file) if output_file else None,
                        verbose,
                        quiet,
                    )
                )
            except SystemExit as e:
                if e.code == 1:
                    total_vulnerabilities += 1
                elif e.code != 0:
                    failed_scans += 1

        except Exception as e:
            failed_scans += 1
            if not quiet:
                console.print(f"❌ Failed to scan {file_path}: {str(e)}", style="red")

    if not quiet:
        console.print("\n📊 Batch scan complete:", style="bold")
        console.print(f"   Files scanned: {len(files)}")
        console.print(f"   Files with vulnerabilities: {total_vulnerabilities}")
        console.print(f"   Failed scans: {failed_scans}")

    if total_vulnerabilities > 0 or failed_scans > 0:
        sys.exit(1)


@cli.command()
def info():
    """Show information about supported file types and usage examples."""
    info_text = """
[bold blue]📋 Supported File Types:[/bold blue]

• [green]requirements.txt[/green] - Python pip dependencies
• [green]package.json[/green] - Node.js npm dependencies

[bold blue]🔍 Detection Methods:[/bold blue]

• [yellow]Registry Existence Check[/yellow] - Identifies non-existent packages (CRITICAL)
• [yellow]ML Pattern Analysis[/yellow] - Detects AI-generated naming patterns  
• [yellow]Heuristic Analysis[/yellow] - Analyzes package metadata and behavior
• [yellow]Typosquatting Detection[/yellow] - Finds packages similar to popular ones

[bold blue]🚨 Risk Levels:[/bold blue]

• [red]CRITICAL[/red] - Package doesn't exist (exploitable vulnerability)
• [yellow]HIGH[/yellow] - Package exists but highly suspicious
• [blue]MEDIUM[/blue] - Package has some suspicious characteristics
• [green]LOW[/green] - Package appears legitimate

[bold blue]🌍 Environment Variables:[/bold blue]

• [cyan]DEP_HALLUCINATOR_RATE_LIMIT[/cyan] - Set default rate limit
• [cyan]DEP_HALLUCINATOR_MAX_CONCURRENT[/cyan] - Set max concurrent requests
• [cyan]DEP_HALLUCINATOR_TIMEOUT[/cyan] - Set request timeout
• [cyan]DEP_HALLUCINATOR_FAIL_ON_HIGH[/cyan] - Fail on HIGH risk packages

[bold blue]📄 Configuration Files:[/bold blue]

• [green].dep-hallucinator.json[/green] - Project-level config
• [green]~/.config/dep-hallucinator/config.json[/green] - User-level config
• [green]~/.dep-hallucinator.json[/green] - User home config

[bold blue]💡 Usage Examples:[/bold blue]

  # Basic scan
  dep-hallucinator scan requirements.txt
  
  # Custom rate limiting
  dep-hallucinator scan requirements.txt --rate-limit 5
  
  # JSON output for automation
  dep-hallucinator scan requirements.txt --output-format json
  
  # Batch scanning
  dep-hallucinator batch requirements.txt package.json
  
  # CI/CD integration (quiet mode)
  dep-hallucinator scan requirements.txt --quiet
  
  # Generate sample config
  dep-hallucinator config init
"""
    console.print(
        Panel(
            info_text,
            title="[bold]Dep-Hallucinator Information[/bold]",
            border_style="blue",
        )
    )


@cli.group()
def config():
    """Configuration management commands."""
    pass


@config.command("init")
@click.option(
    "--path",
    type=click.Path(),
    default=".dep-hallucinator.json",
    help="Path where to create the config file",
    show_default=True,
)
@click.option("--force", is_flag=True, help="Overwrite existing config file")
def config_init(path: str, force: bool):
    """Create a sample configuration file."""
    config_path = Path(path)

    if config_path.exists() and not force:
        console.print(f"⚠️  Config file already exists at {config_path}", style="yellow")
        console.print("Use --force to overwrite", style="dim")
        return

    try:
        config_content = create_sample_config()
        with open(config_path, "w", encoding="utf-8") as f:
            f.write(config_content)

        console.print(f"✅ Created configuration file at {config_path}", style="green")
        console.print("Edit this file to customize your settings", style="dim")

    except Exception as e:
        console.print(f"❌ Failed to create config file: {e}", style="red")


@config.command("show")
def config_show():
    """Show current comprehensive configuration settings."""
    current_config = get_config()

    console.print(
        Panel(
            "[bold blue]🔧 Comprehensive Configuration[/bold blue]", border_style="blue"
        )
    )

    console.print("\n[bold cyan]📊 Scan Settings:[/bold cyan]")
    console.print(f"  Rate Limit: {current_config.scan.rate_limit} req/s")
    console.print(f"  Max Concurrent: {current_config.scan.max_concurrent}")
    console.print(f"  Timeout: {current_config.scan.timeout_seconds}s")
    console.print(f"  Retry Attempts: {current_config.scan.retry_attempts}")
    console.print(f"  Fail on High Risk: {current_config.scan.fail_on_high}")

    console.print("\n[bold cyan]🔒 Security Settings:[/bold cyan]")
    console.print(f"  Max File Size: {current_config.security.max_file_size_mb} MB")
    console.print(
        f"  Max Credential Length: {current_config.security.max_credential_length}"
    )
    console.print(f"  Max Input Length: {current_config.security.max_input_length}")
    console.print(
        f"  Min Credential Length: {current_config.security.min_credential_length}"
    )
    console.print(
        f"  Allowed Extensions: {', '.join(current_config.security.allowed_file_extensions)}"
    )

    console.print("\n[bold cyan]🤖 ML Settings:[/bold cyan]")
    console.print(f"  AI Threshold: {current_config.ml.ai_probability_threshold}")
    console.print(
        f"  High Confidence Threshold: {current_config.ml.high_confidence_threshold}"
    )
    console.print(f"  ML Weight: {current_config.ml.ensemble_ml_weight}")
    console.print(f"  Heuristic Weight: {current_config.ml.ensemble_heuristic_weight}")
    console.print(
        f"  Feature Range: [{current_config.ml.min_feature_value}, {current_config.ml.max_feature_value}]"
    )

    console.print("\n[bold cyan]🎯 Heuristic Settings:[/bold cyan]")
    console.print(
        f"  Suspicious Threshold: {current_config.heuristics.suspicious_threshold}"
    )
    console.print(
        f"  Highly Suspicious Threshold: {current_config.heuristics.highly_suspicious_threshold}"
    )
    console.print(
        f"  Weights Sum: {sum(current_config.heuristics.weights.values()):.3f}"
    )

    console.print("\n[bold cyan]🌐 Network Settings:[/bold cyan]")
    for registry, url in current_config.network.registry_urls.items():
        console.print(f"  {registry}: {url}")
    console.print(f"  Connect Timeout: {current_config.network.connect_timeout}s")
    console.print(f"  Read Timeout: {current_config.network.read_timeout}s")
    console.print(f"  User Agent: {current_config.network.user_agent}")

    console.print("\n[bold cyan]📝 Logging Settings:[/bold cyan]")
    console.print(f"  Log Level: {current_config.logging.log_level}")
    console.print(f"  File Logging: {current_config.logging.enable_file_logging}")
    console.print(
        f"  Sensitive Data Masking: {current_config.logging.enable_sensitive_data_masking}"
    )

    console.print("\n[bold cyan]⚡ Performance Settings:[/bold cyan]")
    console.print(f"  Caching Enabled: {current_config.performance.enable_caching}")
    console.print(f"  Cache TTL: {current_config.performance.cache_ttl_seconds}s")
    console.print(f"  Max Cache Size: {current_config.performance.max_cache_size}")
    console.print(f"  Compression: {current_config.performance.enable_compression}")


@config.command("validate")
@click.argument("config_file", type=click.Path(exists=True))
def config_validate(config_file: str):
    """Validate a configuration file."""
    config_path = Path(config_file)
    config_data = load_config_file(config_path)

    if config_data is None:
        console.print(f"❌ Could not load config from {config_file}", style="red")
        return

    try:

        if "scan" in config_data:
            scan_config = config_data["scan"]
            if "rate_limit" in scan_config:
                rate_limit = float(scan_config["rate_limit"])
                if rate_limit <= 0:
                    raise ValueError("rate_limit must be positive")

            if "max_concurrent" in scan_config:
                max_concurrent = int(scan_config["max_concurrent"])
                if max_concurrent <= 0:
                    raise ValueError("max_concurrent must be positive")

        console.print(f"✅ Configuration file {config_file} is valid", style="green")

    except Exception as e:
        console.print(f"❌ Configuration validation failed: {e}", style="red")


@cli.command()
@click.argument(
    "shell", type=click.Choice(["bash", "zsh", "fish"], case_sensitive=False)
)
@click.option(
    "--install",
    is_flag=True,
    help="Install completion script to system location (requires permissions)",
)
def completion(shell: str, install: bool):
    """Generate shell completion scripts.

    Examples:

      dep-hallucinator completion bash

      dep-hallucinator completion bash --install

      dep-hallucinator completion bash > ~/.dep-hallucinator-completion.bash
    """
    scripts = get_completion_scripts()
    script_content = scripts.get(shell.lower())

    if not script_content:
        console.print(f"❌ No completion script available for {shell}", style="red")
        return

    if install:
        install_paths = {
            "bash": [
                "/etc/bash_completion.d/dep-hallucinator",
                "~/.local/share/bash-completion/completions/dep-hallucinator",
            ],
            "zsh": [
                "/usr/share/zsh/site-functions/_dep-hallucinator",
                "~/.local/share/zsh/site-functions/_dep-hallucinator",
            ],
            "fish": [
                "~/.config/fish/completions/dep-hallucinator.fish",
                "/usr/share/fish/vendor_completions.d/dep-hallucinator.fish",
            ],
        }

        paths = install_paths.get(shell.lower(), [])
        installed = False

        for path_str in paths:
            try:
                install_path = Path(path_str).expanduser()
                install_path.parent.mkdir(parents=True, exist_ok=True)

                with open(install_path, "w", encoding="utf-8") as f:
                    f.write(script_content)

                console.print(
                    f"✅ Installed {shell} completion to {install_path}", style="green"
                )

                if shell.lower() == "bash":
                    console.print(
                        "Run: source ~/.bashrc or restart your shell", style="dim"
                    )
                elif shell.lower() == "zsh":
                    console.print(
                        "Add to ~/.zshrc: autoload -U compinit && compinit", style="dim"
                    )
                elif shell.lower() == "fish":
                    console.print(
                        "Completion will be available in new fish sessions", style="dim"
                    )

                installed = True
                break

            except PermissionError:
                continue
            except Exception as e:
                console.print(
                    f"⚠️  Could not install to {install_path}: {e}", style="yellow"
                )
                continue

        if not installed:
            console.print(
                "❌ Could not install completion script automatically.", style="red"
            )
            console.print("Try running with sudo or save manually:", style="dim")
            console.print(
                f"dep-hallucinator completion {shell} > ~/.dep-hallucinator-completion.{shell}",
                style="dim",
            )
    else:
        print(script_content)


@cli.group()
def cache():
    """Cache management commands."""
    pass


@cache.command("stats")
def cache_stats():
    """Show cache statistics and performance metrics."""
    cache_manager = get_cache_manager()
    stats = cache_manager.get_stats()

    console.print(
        Panel(
            "[bold blue]📊 Cache Performance Statistics[/bold blue]",
            border_style="blue",
        )
    )

    console.print("\n[bold cyan]Performance Metrics:[/bold cyan]")
    console.print(f"  Cache Enabled: {'✅ Yes' if stats['enabled'] else '❌ No'}")
    console.print(f"  Hit Rate: {stats['hit_rate_percent']:.1f}%")
    console.print(f"  Total Requests: {stats['total_requests']}")
    console.print(f"  Cache Hits: {stats['hits']}")
    console.print(f"  Cache Misses: {stats['misses']}")

    console.print("\n[bold cyan]Cache Management:[/bold cyan]")
    console.print(f"  Current Size: {stats['current_size']} entries")
    console.print(f"  Max Size: {stats['max_size']} entries")
    console.print(f"  Size Utilization: {stats['size_utilization_percent']:.1f}%")
    console.print(f"  Evictions: {stats['evictions']}")
    console.print(f"  Expired Removals: {stats['expired_removals']}")
    console.print(f"  Manual Removals: {stats['manual_removals']}")

    console.print("\n[bold cyan]Configuration:[/bold cyan]")
    console.print(
        f"  Default TTL: {stats['default_ttl_seconds']} seconds ({stats['default_ttl_seconds'] // 60} minutes)"
    )

    # Performance assessment
    if stats["total_requests"] > 0:
        if stats["hit_rate_percent"] >= 50:
            hit_status = "🟢 Excellent"
        elif stats["hit_rate_percent"] >= 30:
            hit_status = "🟡 Good"
        else:
            hit_status = "🔴 Poor"

        console.print("\n[bold cyan]Assessment:[/bold cyan]")
        console.print(f"  Cache Performance: {hit_status}")

        if stats["hit_rate_percent"] < 30:
            console.print(
                "  💡 Consider increasing TTL or checking for duplicate scans"
            )


@cache.command("entries")
@click.option("--limit", default=20, help="Maximum number of entries to show", type=int)
@click.option(
    "--sort-by",
    type=click.Choice(["access_count", "age", "expiry"], case_sensitive=False),
    default="access_count",
    help="Sort entries by field",
)
def cache_entries(limit: int, sort_by: str):
    """Show current cache entries with details."""
    cache_manager = get_cache_manager()
    entries = cache_manager.get_entries_info()

    if not entries:
        console.print("📭 Cache is empty", style="yellow")
        return

    # Sort entries
    if sort_by == "age":
        entries.sort(key=lambda x: x["age_seconds"], reverse=True)
    elif sort_by == "expiry":
        entries.sort(key=lambda x: x["seconds_until_expiry"])
    # access_count is already the default sort

    # Limit entries
    entries = entries[:limit]

    console.print(
        Panel(
            f"[bold blue]📦 Cache Entries (showing {len(entries)} of {cache_manager.size()})[/bold blue]",
            border_style="blue",
        )
    )

    for i, entry in enumerate(entries, 1):
        status_icon = "❌ Expired" if entry["is_expired"] else "✅ Fresh"

        console.print(
            f"\n[bold cyan]{i}. {entry['package_name']} ({entry['registry_type']})[/bold cyan]"
        )
        console.print(f"  Status: {status_icon}")
        console.print(
            f"  Age: {entry['age_seconds']:.0f}s ({entry['age_seconds'] // 60:.0f}m)"
        )
        console.print(
            f"  TTL: {entry['ttl_seconds']}s ({entry['ttl_seconds'] // 60:.0f}m)"
        )
        console.print(f"  Access Count: {entry['access_count']}")

        if not entry["is_expired"]:
            console.print(
                f"  Expires In: {entry['seconds_until_expiry']:.0f}s ({entry['seconds_until_expiry'] // 60:.0f}m)"
            )


@cache.command("clear")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def cache_clear(confirm: bool):
    """Clear all cache entries."""
    cache_manager = get_cache_manager()
    current_size = cache_manager.size()

    if current_size == 0:
        console.print("📭 Cache is already empty", style="yellow")
        return

    if not confirm:
        if not click.confirm(
            f"Are you sure you want to clear {current_size} cache entries?"
        ):
            console.print("❌ Cache clear cancelled")
            return

    cleared_count = cache_manager.clear()
    console.print(f"✅ Cleared {cleared_count} cache entries", style="green")


@cache.command("cleanup")
def cache_cleanup():
    """Remove expired cache entries."""
    cache_manager = get_cache_manager()
    cleanup_stats = cache_manager.cleanup_now()

    console.print(
        Panel("[bold blue]🧹 Cache Cleanup Results[/bold blue]", border_style="blue")
    )
    console.print(f"  Initial Size: {cleanup_stats['initial_size']} entries")
    console.print(f"  Final Size: {cleanup_stats['final_size']} entries")
    console.print(f"  Removed: {cleanup_stats['removed_count']} expired entries")

    if cleanup_stats["removed_count"] > 0:
        console.print(
            f"✅ Cleaned up {cleanup_stats['removed_count']} expired entries",
            style="green",
        )
    else:
        console.print("✨ No expired entries found", style="dim")


@cache.command("remove")
@click.argument("package_name")
@click.option(
    "--registry",
    type=click.Choice(["pypi", "npm", "maven", "crates", "go"], case_sensitive=False),
    default="pypi",
    help="Registry type",
)
def cache_remove(package_name: str, registry: str):
    """Remove a specific package from cache."""
    cache_manager = get_cache_manager()

    if cache_manager.remove(package_name, registry):
        console.print(
            f"✅ Removed {package_name} ({registry}) from cache", style="green"
        )
    else:
        console.print(
            f"❌ Package {package_name} ({registry}) not found in cache", style="yellow"
        )


@cache.command("ml-stats")
def cache_ml_stats():
    """Show ML engine cache statistics."""
    try:
        from .ml_engine import get_ml_engine_cache_stats

        stats = get_ml_engine_cache_stats()

        console.print(
            Panel(
                "[bold blue]🤖 ML Engine Cache Statistics[/bold blue]",
                border_style="blue",
            )
        )

        console.print("\n[bold cyan]Cache Status:[/bold cyan]")
        console.print(f"  Cached: {'✅ Yes' if stats['is_cached'] else '❌ No'}")
        console.print(f"  Access Count: {stats['access_count']}")

        if stats["is_cached"]:
            console.print("\n[bold cyan]Cache Details:[/bold cyan]")
            console.print(
                f"  Age: {stats['age_seconds']:.1f}s ({stats['age_seconds'] // 60:.1f}m)"
            )
            console.print(
                f"  TTL: {stats['cache_ttl_seconds']}s ({stats['cache_ttl_seconds'] // 60}m)"
            )
            console.print(
                f"  Expires In: {stats['time_until_expiry']:.1f}s ({stats['time_until_expiry'] // 60:.1f}m)"
            )
            console.print(f"  Max Access Count: {stats['max_access_count']}")
            console.print(
                f"  Is Expired: {'❌ Yes' if stats['is_expired'] else '✅ No'}"
            )

            if "approximate_size_bytes" in stats:
                size_mb = stats["approximate_size_bytes"] / (1024 * 1024)
                console.print(f"  Approximate Size: {size_mb:.2f} MB")

            # Performance assessment
            access_rate = (
                stats["access_count"] / stats["age_seconds"]
                if stats["age_seconds"] > 0
                else 0
            )
            console.print("\n[bold cyan]Performance:[/bold cyan]")
            console.print(f"  Access Rate: {access_rate:.2f} accesses/second")

            if access_rate > 1:
                console.print(
                    "  📊 High usage - caching is providing good performance benefit"
                )
            elif access_rate > 0.1:
                console.print("  📊 Moderate usage - caching is providing some benefit")
            else:
                console.print("  📊 Low usage - consider reducing TTL to save memory")

    except Exception as e:
        console.print(f"❌ Error getting ML cache stats: {e}", style="red")


@cache.command("ml-clear")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def cache_ml_clear(confirm: bool):
    """Clear the ML engine cache, forcing model recreation."""
    try:
        from .ml_engine import get_ml_engine_cache_stats, reset_ml_engine_cache

        stats = get_ml_engine_cache_stats()
        if not stats["is_cached"]:
            console.print("📭 ML engine cache is already empty", style="yellow")
            return

        if not confirm:
            age_minutes = stats["age_seconds"] // 60
            if not click.confirm(
                f"Clear ML engine cache (age: {age_minutes}m, accesses: {stats['access_count']})?"
            ):
                console.print("❌ ML cache clear cancelled")
                return

        if reset_ml_engine_cache():
            console.print("✅ ML engine cache cleared successfully", style="green")
        else:
            console.print("❌ Failed to clear ML engine cache", style="red")

    except Exception as e:
        console.print(f"❌ Error clearing ML cache: {e}", style="red")


@cache.command("ml-configure")
@click.option("--ttl", type=int, help="Time-to-live in seconds for ML engine cache")
@click.option("--max-access", type=int, help="Maximum access count before recreation")
def cache_ml_configure(ttl: Optional[int], max_access: Optional[int]):
    """Configure ML engine cache parameters."""
    try:
        from .ml_engine import configure_ml_engine_cache, get_ml_engine_cache_stats

        if ttl is None and max_access is None:
            # Show current configuration
            stats = get_ml_engine_cache_stats()
            console.print(
                Panel(
                    "[bold blue]🤖 ML Engine Cache Configuration[/bold blue]",
                    border_style="blue",
                )
            )
            console.print(
                f"  TTL: {stats['cache_ttl_seconds']}s ({stats['cache_ttl_seconds'] // 60}m)"
            )
            console.print(f"  Max Access Count: {stats['max_access_count']}")
            return

        if configure_ml_engine_cache(ttl, max_access):
            changes = []
            if ttl is not None:
                changes.append(f"TTL: {ttl}s ({ttl // 60}m)")
            if max_access is not None:
                changes.append(f"Max Access: {max_access}")

            console.print(
                f"✅ ML cache configured: {', '.join(changes)}", style="green"
            )
        else:
            console.print("❌ Failed to configure ML engine cache", style="red")

    except Exception as e:
        console.print(f"❌ Error configuring ML cache: {e}", style="red")


@cli.group()
def allowlist():
    """Manage trusted package allowlist."""
    pass


@allowlist.command("add")
@click.argument("package_name")
@click.option(
    "--pattern-type",
    type=click.Choice(["exact", "pattern", "prefix"], case_sensitive=False),
    default="exact",
    help="Type of pattern matching",
)
@click.option("--reason", help="Reason for adding to allowlist")
def allowlist_add(package_name: str, pattern_type: str, reason: str):
    """Add a package to the allowlist."""
    try:
        if not package_name.strip():
            raise click.ClickException("Package name cannot be empty")

        manager = get_package_list_manager()
        match_type = MatchType(pattern_type.lower())

        if manager.add_to_allowlist(package_name, match_type, reason):
            console.print(f"✅ Added '{package_name}' to allowlist", style="green")
        else:
            console.print(
                f"⚠️  Package '{package_name}' already in allowlist", style="yellow"
            )

    except Exception as e:
        raise click.ClickException(f"Failed to add to allowlist: {str(e)}")


@allowlist.command("remove")
@click.argument("package_name")
def allowlist_remove(package_name: str):
    """Remove a package from the allowlist."""
    try:
        manager = get_package_list_manager()

        if manager.remove_from_allowlist(package_name):
            console.print(f"✅ Removed '{package_name}' from allowlist", style="green")
        else:
            console.print(
                f"⚠️  Package '{package_name}' not found in allowlist", style="yellow"
            )

    except Exception as e:
        raise click.ClickException(f"Failed to remove from allowlist: {str(e)}")


@allowlist.command("list")
@click.option(
    "--ecosystem",
    type=click.Choice(["pip", "npm", "maven", "crates", "go"], case_sensitive=False),
    help="Filter by ecosystem",
)
def allowlist_list(ecosystem: Optional[str]):
    """List all packages in the allowlist."""
    try:
        manager = get_package_list_manager()
        entries = manager.get_allowlist(ecosystem)

        if not entries:
            console.print("📋 Allowlist is empty", style="blue")
            return

        console.print(f"📋 Allowlist ({len(entries)} entries):", style="blue")
        for entry in entries:
            ecosystems_str = ", ".join(entry.ecosystems) if entry.ecosystems else "all"
            console.print(
                f"  • {entry.name} ({entry.match_type.value}) - {ecosystems_str}"
            )
            if entry.reason:
                console.print(f"    📝 {entry.reason}", style="dim")

    except Exception as e:
        raise click.ClickException(f"Failed to list allowlist: {str(e)}")


@cli.group()
def denylist():
    """Manage dangerous package denylist."""
    pass


@denylist.command("add")
@click.argument("package_name")
@click.option(
    "--pattern-type",
    type=click.Choice(["exact", "pattern", "prefix"], case_sensitive=False),
    default="exact",
    help="Type of pattern matching",
)
@click.option("--reason", help="Reason for adding to denylist")
def denylist_add(package_name: str, pattern_type: str, reason: str):
    """Add a package to the denylist."""
    try:
        if not package_name.strip():
            raise click.ClickException("Package name cannot be empty")

        manager = get_package_list_manager()
        match_type = MatchType(pattern_type.lower())

        if manager.add_to_denylist(package_name, match_type, reason):
            console.print(f"🚫 Added '{package_name}' to denylist", style="red")
        else:
            console.print(
                f"⚠️  Package '{package_name}' already in denylist", style="yellow"
            )

    except Exception as e:
        raise click.ClickException(f"Failed to add to denylist: {str(e)}")


@denylist.command("remove")
@click.argument("package_name")
def denylist_remove(package_name: str):
    """Remove a package from the denylist."""
    try:
        manager = get_package_list_manager()

        if manager.remove_from_denylist(package_name):
            console.print(f"✅ Removed '{package_name}' from denylist", style="green")
        else:
            console.print(
                f"⚠️  Package '{package_name}' not found in denylist", style="yellow"
            )

    except Exception as e:
        raise click.ClickException(f"Failed to remove from denylist: {str(e)}")


@denylist.command("list")
@click.option(
    "--ecosystem",
    type=click.Choice(["pip", "npm", "maven", "crates", "go"], case_sensitive=False),
    help="Filter by ecosystem",
)
def denylist_list(ecosystem: Optional[str]):
    """List all packages in the denylist."""
    try:
        manager = get_package_list_manager()
        entries = manager.get_denylist(ecosystem)

        if not entries:
            console.print("📋 Denylist is empty", style="blue")
            return

        console.print(f"📋 Denylist ({len(entries)} entries):", style="red")
        for entry in entries:
            ecosystems_str = ", ".join(entry.ecosystems) if entry.ecosystems else "all"
            console.print(
                f"  🚫 {entry.name} ({entry.match_type.value}) - {ecosystems_str}"
            )
            if entry.reason:
                console.print(f"    📝 {entry.reason}", style="dim")

    except Exception as e:
        raise click.ClickException(f"Failed to list denylist: {str(e)}")


@cli.group()
def forensic():
    """Forensic analysis and historical tracking commands."""
    pass


@forensic.command("history")
@click.option(
    "--file-path", type=click.Path(exists=True), help="Filter by specific file path"
)
@click.option("--limit", default=20, type=int, help="Maximum number of scans to show")
def forensic_history(file_path: Optional[str], limit: int):
    """Show scan history for forensic analysis."""
    try:
        forensic_manager = get_forensic_manager()
        history = forensic_manager.get_scan_history(file_path, limit)

        if not history:
            console.print("📊 No scan history found", style="yellow")
            return

        console.print(
            f"\n📊 [bold blue]Scan History[/bold blue] ({len(history)} scans)"
        )

        for scan in history:
            timestamp = datetime.fromisoformat(
                scan.scan_timestamp.replace("Z", "+00:00")
            )
            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")

            console.print(f"\n🔍 Scan ID: [cyan]{scan.scan_id[:12]}...[/cyan]")
            console.print(f"   📁 File: {scan.file_path}")
            console.print(f"   ⏰ Time: {formatted_time}")
            console.print(f"   📦 Dependencies: {scan.total_dependencies}")
            console.print(f"   ⚡ Duration: {scan.scan_duration_ms}ms")

            if scan.scan_options:
                console.print(
                    f"   ⚙️  Options: {', '.join(f'{k}={v}' for k, v in scan.scan_options.items())}",
                    style="dim",
                )

    except Exception as e:
        console.print(f"❌ Error accessing forensic history: {str(e)}", style="red")


@forensic.command("timeline")
@click.argument("package_name")
@click.option(
    "--file-path", type=click.Path(exists=True), help="Filter by specific file path"
)
def forensic_timeline(package_name: str, file_path: Optional[str]):
    """Show timeline of a specific package across scans."""
    try:
        forensic_manager = get_forensic_manager()
        timeline = forensic_manager.get_package_timeline(package_name, file_path)

        if not timeline:
            console.print(
                f"📊 No timeline data found for package: {package_name}", style="yellow"
            )
            return

        console.print(f"\n📈 [bold blue]Package Timeline: {package_name}[/bold blue]")

        for entry in timeline:
            timestamp = datetime.fromisoformat(
                entry["timestamp"].replace("Z", "+00:00")
            )
            formatted_time = timestamp.strftime("%Y-%m-%d %H:%M:%S")

            risk_color = {
                "CRITICAL": "red",
                "HIGH": "yellow",
                "MEDIUM": "blue",
                "LOW": "green",
            }.get(entry["risk_level"], "white")

            console.print(
                f"  {formatted_time} │ [{risk_color}]{entry['risk_level']}[/{risk_color}] │ v{entry['version'] or 'unknown'}"
            )

            if entry["suspicion_score"]:
                score = int(entry["suspicion_score"] * 100)
                console.print(
                    f"                     │ Suspicion: {score}%", style="dim"
                )

            if entry["ml_probability"]:
                ml_score = int(entry["ml_probability"] * 100)
                console.print(f"                     │ ML: {ml_score}%", style="dim")

    except Exception as e:
        console.print(f"❌ Error accessing package timeline: {str(e)}", style="red")


@forensic.command("cleanup")
@click.option("--retention-days", default=90, type=int, help="Retention period in days")
@click.option("--confirm", is_flag=True, help="Skip confirmation prompt")
def forensic_cleanup(retention_days: int, confirm: bool):
    """Clean up old forensic data."""
    if not confirm:
        console.print(
            f"⚠️  This will delete scan data older than {retention_days} days."
        )
        if not click.confirm("Continue?"):
            console.print("Operation cancelled", style="yellow")
            return

    try:
        forensic_manager = get_forensic_manager()
        result = forensic_manager.cleanup_old_data(retention_days)

        deleted_count = result.get("deleted_scans", 0)
        if deleted_count > 0:
            console.print(
                f"✅ Cleaned up {deleted_count} old scan records", style="green"
            )
        else:
            console.print("ℹ️  No old data to clean up", style="blue")

    except Exception as e:
        console.print(f"❌ Error during cleanup: {str(e)}", style="red")


if __name__ == "__main__":
    cli()
