import re
from models import Finding, Type, Severity, Confidence
from sast.rules import SECRET_PATTERNS, LOW_CONFIDENCE_PATTERNS


def detect_secrets(code):
    findings = []
    for i, line in enumerate(code.split('\n'), 1):
        for secret_type, pattern in SECRET_PATTERNS.items():
            match = re.search(pattern, line)
            if match:
                findings.append(create_finding(i, secret_type, match.group(0), Confidence.HIGH))
        for secret_type, pattern in LOW_CONFIDENCE_PATTERNS.items():
            match = re.search(pattern, line)
            if match:
                findings.append(create_finding(i, secret_type, match.group(0), Confidence.LOW))

    return findings

def create_finding(line, description, snippet, confidence):
    return Finding(
        type=Type.SECRETS,
        line=line,
        severity=Severity.CRITICAL,
        confidence=confidence,
        snippet=snippet,
        description=description
    )