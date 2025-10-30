from securefix.cve.db import query_osv
from securefix.models import OSVFinding
import sys

# Import tomllib/tomli at module level for easier testing
if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # Will be checked in scan_pyproject


def scan_requirements(requirements_file):
    """Scan a requirements.txt file for CVE vulnerabilities."""
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


def scan_pyproject(pyproject_file):
    """Scan a pyproject.toml file for CVE vulnerabilities."""
    findings = []

    # Check if tomllib is available
    if tomllib is None:
        raise ImportError(
            "tomli is required for Python < 3.11. Install with: pip install tomli"
        )

    try:
        with open(pyproject_file, 'rb') as f:
            pyproject_data = tomllib.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(f"pyproject.toml not found at {pyproject_file}")
    except Exception as e:
        raise ValueError(f"Error parsing pyproject.toml: {e}")

    # Extract dependencies from [project.dependencies]
    dependencies = pyproject_data.get('project', {}).get('dependencies', [])

    for dep_spec in dependencies:
        # Parse dependency specification (e.g., "requests>=2.32.0,<3.0.0")
        package_name, version = _parse_dependency_spec(dep_spec)

        if package_name and version:
            cves = query_osv(package_name, version)
            if cves:
                findings.append(OSVFinding(package_name, version, cves, pyproject_file))

    return findings


def _parse_dependency_spec(dep_spec):
    """
    Parse a PEP 508 dependency specification to extract package name and version.

    Examples:
        "requests==2.32.0" -> ("requests", "2.32.0")
        "requests>=2.32.0,<3.0.0" -> ("requests", "2.32.0")
        "click>=8.3.0,<9.0.0" -> ("click", "8.3.0")

    Returns:
        Tuple of (package_name, version) or (None, None) if parsing fails
    """
    try:
        from packaging.requirements import Requirement
        from packaging.specifiers import SpecifierSet

        req = Requirement(dep_spec)
        package_name = req.name

        # Extract version from specifiers
        if req.specifier:
            # Get the minimum version from the specifier set
            # For specs like ">=2.32.0,<3.0.0", we want to check the minimum version
            version = _extract_version_from_specifier(req.specifier)
            return package_name, version
        else:
            # No version specifier, can't check CVEs
            return None, None

    except Exception as e:
        print(f"Warning: Could not parse dependency spec '{dep_spec}': {e}")
        return None, None


def _extract_version_from_specifier(specifier_set):
    """
    Extract a version string from a SpecifierSet.

    Prioritizes:
    1. Exact version (==)
    2. Minimum version (>=, >)
    3. Maximum version (<, <=)
    """
    # First pass: look for exact version (highest priority)
    for spec in specifier_set:
        if spec.operator == "==":
            return spec.version

    # Second pass: look for minimum version
    for spec in specifier_set:
        if spec.operator in (">=", ">"):
            return spec.version

    # Third pass: look for maximum version
    for spec in specifier_set:
        if spec.operator in ("<", "<="):
            return spec.version

    return None


def scan_dependencies(dependency_file):
    """
    Auto-detect and scan either requirements.txt or pyproject.toml.

    Args:
        dependency_file: Path to requirements.txt or pyproject.toml

    Returns:
        List of OSVFinding objects
    """
    if dependency_file.endswith('.toml'):
        return scan_pyproject(dependency_file)
    else:
        return scan_requirements(dependency_file)