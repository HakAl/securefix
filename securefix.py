import os
import click
import json
from datetime import datetime
from pathlib import Path
import sast.scanner as sast_scanner
import cve.scanner as cve_scanner
from models import ScanResult
from remediation.corpus_builder import DocumentProcessor


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


@cli.command()
@click.option('--corpus-path', '-c', type=click.Path(),
              default='./remediation/corpus',
              help='Path to security corpus files')
@click.option('--rebuild', is_flag=True,
              help='Rebuild vector store even if one exists')
@click.option('--persist-dir', type=click.Path(),
              default='./chroma_db',
              help='Directory to store vector database')
def ingest(corpus_path, rebuild, persist_dir):
    """Build vector database from security corpus"""
    import time
    start_time = time.time()

    # Ensure corpus directory exists
    if not os.path.exists(corpus_path):
        click.echo(f"Creating corpus directory: {corpus_path}")
        os.makedirs(corpus_path, exist_ok=True)
        click.echo(f"Please add security corpus files and run again")
        click.echo(f"Supported formats: .csv, .md, .yaml, .yml")
        return

    # Check if already exists
    if os.path.exists(persist_dir) and not rebuild:
        click.echo(f"Vector database already exists at {persist_dir}")
        click.echo("Use --rebuild to recreate it")
        return

    # Clean up if rebuilding
    if os.path.exists(persist_dir) and rebuild:
        import shutil
        click.echo(f"Removing old database...")
        shutil.rmtree(persist_dir)

    # Initialize processor
    try:
        processor = DocumentProcessor(persist_directory=persist_dir)
    except Exception as e:
        click.echo(f"Failed to initialize: {e}", err=True)
        return

    # Process documents
    click.echo(f"Processing corpus from {corpus_path}...")
    click.echo("(This may take several minutes...)")

    processing_start = time.time()
    try:
        result = processor.process_documents(corpus_path)
    except Exception as e:
        click.echo(f"Failed to build vector database: {e}", err=True)
        return
    processing_time = time.time() - processing_start

    if result is None:
        click.echo("No documents were successfully processed", err=True)
        return

    vector_store, bm25_index, bm25_chunks = result

    total_time = time.time() - start_time

    # Show statistics
    click.echo(f"\nVector database built successfully!")
    click.echo(f"\nStatistics:")
    click.echo(f"  Chunks indexed: {len(bm25_chunks)}")
    click.echo(f"  Storage location: {persist_dir}")
    click.echo(f"  Corpus source: {corpus_path}")
    click.echo(f"\nPerformance:")
    click.echo(f"  Processing time: {processing_time:.2f}s")
    click.echo(f"  Total time: {total_time:.2f}s")
    click.echo(f"  Average: {processing_time / len(bm25_chunks) * 1000:.1f}ms per chunk")
    click.echo(f"\nReady to use with: securefix fix <report.json>")

if __name__ == '__main__':
    cli()