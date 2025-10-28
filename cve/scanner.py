from cve.db import query_osv
from models import OSVFinding


def scan_requirements(requirements_file):
    findings = []
    with open(requirements_file) as f:
        for line in f:
            line = line.strip()
            if '==' in line:
                package, version = line.strip().split('==')
                cves = query_osv(package, version)
                if cves:
                    findings.append(OSVFinding(package, version, cves))
    return findings