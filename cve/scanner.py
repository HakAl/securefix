import requests

from models import OSVRequest, OSVFinding

# Hardcoded for demo reliability
KNOWN_VULNERABILITIES = {
    ("flask", "0.12"): ["CVE-2018-1000656"],
    ("log4j", "2.14.1"): ["CVE-2021-44228"],
    ("django", "2.2.0"): ["CVE-2019-14234"]
}


def check_osv_api(package, version):
    """Query OSV database for real vulnerabilities"""
    try:
        request = OSVRequest(name=package, ecosystem="PyPI", version=version)
        response = requests.post(
            "https://api.osv.dev/v1/query",
            json=request.to_dict(),
            timeout=5
        )
        response.raise_for_status()
        if response.status_code == 200:
            return [vuln['id'] for vuln in response.json().get('vulns', [])]
    except (requests.RequestException, KeyError, ValueError):
        pass
    return []


def scan_dependencies(requirements_file):
    findings = []
    with open(requirements_file) as f:
        for line in f:
            line = line.strip()
            if '==' in line:
                package, version = line.strip().split('==')
                cves = check_osv_api(package, version)
                if cves:
                    findings.append(OSVFinding(package, version, cves))
    return findings