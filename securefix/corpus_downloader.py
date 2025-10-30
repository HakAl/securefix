"""
Utility to download security corpus files from public sources.
"""
import os
import click
import requests
from zipfile import ZipFile
from io import BytesIO
from pathlib import Path
import shutil


def download_cwe(corpus_path: str) -> bool:
    """Download CWE vulnerability database"""
    try:
        click.echo("→ Downloading CWE Database...")
        url = "https://cwe.mitre.org/data/csv/2000.csv.zip"

        response = requests.get(url, timeout=30)
        response.raise_for_status()

        cwe_dir = os.path.join(corpus_path, 'cwe')
        os.makedirs(cwe_dir, exist_ok=True)

        with ZipFile(BytesIO(response.content)) as zip_file:
            zip_file.extractall(cwe_dir)

        click.echo("  ✓ CWE Database downloaded")
        return True

    except Exception as e:
        click.echo(f"  ✗ Failed: {e}", err=True)
        return False


def download_owasp_cheatsheets(corpus_path: str) -> bool:
    """Download OWASP Cheat Sheet Series"""
    try:
        click.echo("→ Downloading OWASP Cheat Sheets...")
        url = "https://github.com/OWASP/CheatSheetSeries/archive/refs/heads/master.zip"

        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()

        # Download with progress
        total_size = int(response.headers.get('content-length', 0))
        with click.progressbar(length=total_size, label='Downloading') as bar:
            content = BytesIO()
            for chunk in response.iter_content(chunk_size=8192):
                content.write(chunk)
                bar.update(len(chunk))

        click.echo("  Extracting...")
        with ZipFile(content) as zip_file:
            # Extract only the cheatsheets directory
            members = [m for m in zip_file.namelist()
                       if m.startswith('CheatSheetSeries-master/cheatsheets/')
                       and m.endswith('.md')]

            cheatsheets_dir = os.path.join(corpus_path, 'cheatsheets')
            os.makedirs(cheatsheets_dir, exist_ok=True)

            for member in members:
                filename = os.path.basename(member)
                if filename:
                    source = zip_file.open(member)
                    target_path = os.path.join(cheatsheets_dir, filename)
                    with open(target_path, 'wb') as target:
                        target.write(source.read())

        click.echo(f"  ✓ Downloaded {len(members)} OWASP cheat sheets")
        return True

    except Exception as e:
        click.echo(f"  ✗ Failed: {e}", err=True)
        return False


def download_pypa_advisories(corpus_path: str) -> bool:
    """Download PyPA Security Advisory Database"""
    try:
        click.echo("→ Downloading PyPA Security Advisories...")
        url = "https://github.com/pypa/advisory-database/archive/refs/heads/main.zip"

        response = requests.get(url, stream=True, timeout=60)
        response.raise_for_status()

        # Download with progress
        total_size = int(response.headers.get('content-length', 0))
        with click.progressbar(length=total_size, label='Downloading') as bar:
            content = BytesIO()
            for chunk in response.iter_content(chunk_size=8192):
                content.write(chunk)
                bar.update(len(chunk))

        click.echo("  Extracting...")
        with ZipFile(content) as zip_file:
            # Extract only YAML files from vulns directory
            members = [m for m in zip_file.namelist()
                       if m.startswith('advisory-database-main/vulns/')
                       and m.endswith('.yaml')]

            pypa_dir = os.path.join(corpus_path, 'pypa')
            os.makedirs(pypa_dir, exist_ok=True)

            for member in members:
                filename = os.path.basename(member)
                if filename:
                    source = zip_file.open(member)
                    target_path = os.path.join(pypa_dir, filename)
                    with open(target_path, 'wb') as target:
                        target.write(source.read())

        click.echo(f"  ✓ Downloaded {len(members)} PyPA advisories")
        return True

    except Exception as e:
        click.echo(f"  ✗ Failed: {e}", err=True)
        return False


@click.command()
@click.option('--corpus-path', '-c', type=click.Path(),
              default='./remediation/corpus',
              help='Path to download corpus files to (default: ./remediation/corpus)')
@click.option('--skip-cwe', is_flag=True,
              help='Skip downloading CWE database')
@click.option('--skip-owasp', is_flag=True,
              help='Skip downloading OWASP cheat sheets')
@click.option('--skip-pypa', is_flag=True,
              help='Skip downloading PyPA advisories')
def download_corpus(corpus_path, skip_cwe, skip_owasp, skip_pypa):
    """Download security corpus files from public sources"""

    click.echo("=" * 70)
    click.echo("SecureFix - Corpus Downloader")
    click.echo("=" * 70)
    click.echo(f"\nDownloading to: {corpus_path}\n")

    # Create corpus directory
    os.makedirs(corpus_path, exist_ok=True)

    results = []

    # Download each source
    if not skip_cwe:
        results.append(('CWE', download_cwe(corpus_path)))

    if not skip_owasp:
        results.append(('OWASP', download_owasp_cheatsheets(corpus_path)))

    if not skip_pypa:
        results.append(('PyPA', download_pypa_advisories(corpus_path)))

    # Summary
    click.echo("\n" + "=" * 70)
    click.echo("Download Summary")
    click.echo("=" * 70)

    success_count = sum(1 for _, success in results if success)
    total_count = len(results)

    for name, success in results:
        status = "✓" if success else "✗"
        click.echo(f"  {status} {name}")

    click.echo(f"\nCompleted: {success_count}/{total_count} sources downloaded")

    if success_count > 0:
        click.echo(f"\n✓ Corpus downloaded to {corpus_path}")
        click.echo("\nNext steps:")
        click.echo("  1. Run: python cli.py ingest")
        click.echo("  2. This will build the vector database (takes 5-10 minutes)")
        click.echo("  3. Then you can scan and fix vulnerabilities!")
    else:
        click.echo("\n✗ No sources were successfully downloaded")
        click.echo("Please check your internet connection and try again")


if __name__ == '__main__':
    download_corpus()