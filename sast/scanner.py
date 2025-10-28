import ast
import os
from sast.detectors.sql_injection import SQLiDetector
from sast.detectors.secrets import detect_secrets


def scan_file(filepath):
    """Scan a Python file for vulnerabilities"""
    with open(filepath, 'r') as f:
        code = f.read()

    findings = []

    # Run AST SQL injection detector
    try:
        tree = ast.parse(code)
        sqli_detector = SQLiDetector()
        sqli_detector.visit(tree)
        findings.extend(sqli_detector.findings)
    except SyntaxError:
        # Handle invalid Python files
        pass

    # Run regex secrets detector
    findings.extend(detect_secrets(code))

    # Add filepath
    for finding in findings:
        finding.file = filepath

    return findings


def scan_directory(directory):
    """Scan all Python files in a directory"""
    findings = []

    for root, dirs, files in os.walk(directory):
        for filename in files:
            if filename.endswith('.py'):
                filepath = os.path.join(root, filename)
                findings.extend(scan_file(filepath))

    return findings


