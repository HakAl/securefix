import click
import json
from datetime import datetime
from pathlib import Path

import sast.scanner as sast_scanner
import cve.scanner as cve_scanner
from models import ScanResult


@click.group()
def cli():
    """SecureFix - Static Application Security Testing with Smart Remediation"""
    pass


@cli.command()
@click.argument('target', type=click.Path(exists=True))
@click.option('--dependencies', '-d', type=click.Path(exists=True),
              help='Path to requirements.txt for CVE scanning')
@click.option('--output', '-o', type=click.Path(), default='report.json',
              help='Output JSON file (default: report.json)')
def scan(target, dependencies, output):
    """Scan TARGET (file or directory) for security vulnerabilities"""

    click.echo(f"Scanning {target}...")

    # SAST scanning
    target_path = Path(target)
    if target_path.is_file():
        sast_findings = sast_scanner.scan_file(str(target_path))
    elif target_path.is_dir():
        sast_findings = sast_scanner.scan_directory(str(target_path))
    else:
        click.echo(f"Error: {target} is not a valid file or directory", err=True)
        return

    click.echo(f"Found {len(sast_findings)} SAST findings")

    # CVE scanning (optional)
    cve_findings = []
    if dependencies:
        click.echo(f"Scanning dependencies in {dependencies}...")
        cve_findings = cve_scanner.scan_requirements(dependencies)
        click.echo(f"Found {len(cve_findings)} vulnerable dependencies")

    # Create report
    scan_result = ScanResult(
        scan_timestamp=datetime.now().isoformat(),
        findings=sast_findings,
        cve_findings=cve_findings
    )

    # Write output
    with open(output, 'w') as f:
        json.dump(scan_result.to_dict(), f, indent=2)

    click.echo(f"\nReport saved to {output}")

    # Print summary
    summary = scan_result.to_dict()['summary']
    click.echo(f"\nSummary:")
    click.echo(f"  Total SAST findings: {summary['total_findings']}")
    click.echo(f"  Total CVE findings: {summary['total_cve_findings']}")
    click.echo(f"  By severity:")
    for severity, count in summary['by_severity'].items():
        if count > 0:
            click.echo(f"    {severity}: {count}")


if __name__ == '__main__':
    cli()