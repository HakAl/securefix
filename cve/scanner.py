from cve.db import query_osv
from models import OSVFinding


def scan_requirements(requirements_file):
    findings = []

    # Try different encodings
    encodings = ['utf-8-sig', 'utf-16', 'utf-16-le', 'utf-16-be', 'latin-1']

    content = None
    for encoding in encodings:
        try:
            with open(requirements_file, encoding=encoding) as f:
                content = f.read()
            break
        except (UnicodeDecodeError, UnicodeError):
            continue

    if content is None:
        raise ValueError(f"Could not decode {requirements_file} with any known encoding")

    for line in content.splitlines():
        line = line.strip()
        if '==' in line:
            package, version = line.split('==')
            cves = query_osv(package, version)
            if cves:
                findings.append(OSVFinding(package, version, cves, requirements_file))

    return findings