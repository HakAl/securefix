from dataclasses import dataclass
from enum import Enum
from dataclasses import asdict


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
    SQL_INJECTION = "SQL Injection"

@dataclass
class Finding:
    type: Type
    line: int
    severity: Severity
    confidence: Confidence

    def to_dict(self):
        data = asdict(self)
        data['type'] = self.type.value
        data['severity'] = self.severity.value
        data['confidence'] = self.confidence.value
        return data