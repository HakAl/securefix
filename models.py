from dataclasses import asdict, dataclass
from enum import Enum
from typing import Optional


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

@dataclass
class Finding:
    type: Type
    line: int
    severity: Severity
    confidence: Confidence
    snippet: Optional[str] = None
    description: Optional[str] = None
    file: Optional[str] = None

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

        return data