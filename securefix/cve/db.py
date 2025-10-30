import requests
from securefix.models import OSVRequest


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

        data = response.json()
        vulns = data.get('vulns', [])

        if vulns:
            return [vuln['id'] for vuln in vulns]

    except (requests.RequestException, KeyError, ValueError) as e:
        print(f"Error querying OSV for {package}=={version}: {e}")
        pass

    return []

