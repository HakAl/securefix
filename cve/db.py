import requests
from models import OSVRequest


def query_osv(package, version):
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

