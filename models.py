from collections import Counter
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

class Type(Enum):
    SECRETS = "Hardcoded Secret"
    SQL_INJECTION = "SQL Injection"
    INSECURE_DESERIALIZATION = "Insecure Deserialization"
    COMMAND_INJECTION = "Command Injection"
    INSECURE_TEMP_FILE = "Insecure Temp File Access"
    XML_VULNERABILITY = "XML Vulnerability"
    CRYPTO_WEAKNESS = "Weak Cryptography"
    XSS = "Cross-Site Scripting"
    DANGEROUS_CODE = "Dangerous Code Execution"
    INSECURE_CONFIG = "Insecure Configuration"
    PATH_TRAVERSAL = "Path Traversal"
    UNKNOWN = "Unknown Vulnerability"

@dataclass
class Finding:
    type: Union[Type, str]
    line: int
    severity: Severity
    confidence: Confidence
    snippet: Optional[str] = None
    description: Optional[str] = None
    file: Optional[str] = None
    bandit_test_id: Optional[str] = None

    def to_dict(self):
        data = {
            'type': self.type.value,
            'line': self.line,
            'severity': self.severity.value,
            'confidence': self.confidence.value,
        }

        if self.snippet is not None:
            data['snippet'] = self.snippet
        if self.description is not None:
            data['description'] = self.description
        if self.file is not None:
            data['file'] = self.file
        if self.bandit_test_id is not None:
            data['bandit_test_id'] = self.bandit_test_id

        return data

@dataclass
class OSVRequest:
    name: str
    ecosystem: str
    version: str

    def to_dict(self):
        return {
            'package': {
                'name': self.name,
                'ecosystem': self.ecosystem
            },
            'version': self.version
        }

@dataclass
class OSVFinding:
    package: str
    version: str
    cves: list[str]
    file: str  # Add this field

    def to_dict(self):
        return {
            'package': self.package,
            'version': self.version,
            'cves': self.cves,
            'file': self.file
        }

@dataclass
class ScanResult:
    scan_timestamp: str
    findings: list
    cve_findings: list

    def to_dict(self):
        severity_counts = Counter(f.severity for f in self.findings)

        return {
            'summary': {
                'total_findings': len(self.findings),
                'total_cve_findings': len(self.cve_findings),
                'by_severity': {
                    'low': severity_counts.get(Severity.LOW, 0),
                    'medium': severity_counts.get(Severity.MEDIUM, 0),
                    'high': severity_counts.get(Severity.HIGH, 0),
                    'critical': severity_counts.get(Severity.CRITICAL, 0)
                },
                'scan_timestamp': self.scan_timestamp,
            },
            'sast_findings': [f.to_dict() for f in self.findings],
            'cve_findings': [c.to_dict() for c in self.cve_findings]
        }