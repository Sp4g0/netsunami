from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ConfigLine:
    number: int
    text: str
    indent: int = 0
    context: str = ""


@dataclass
class ConfigBlock:
    name: str
    lines: list[ConfigLine] = field(default_factory=list)
    vendor: str = "cisco"


@dataclass
class Finding:
    severity: Severity
    title: str
    detail: str
    config_lines: list[int] = field(default_factory=list)
    suggestion: str = ""
    reference: str = ""
    similarity: float = 0.0


@dataclass
class DeviceInfo:
    hostname: str = ""
    model: str = ""
    ios_version: str = ""
    uptime: str = ""
    cpu: str = ""
    memory: str = ""
    serial: str = ""


@dataclass
class AnalysisResult:
    device: str = ""
    timestamp: datetime = field(default_factory=datetime.now)
    config_blocks: list[ConfigBlock] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    session_log: str = ""
