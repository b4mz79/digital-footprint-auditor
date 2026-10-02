from dataclasses import dataclass, field
from enum import Enum


class EngineStatus(str, Enum):

    SUCCESS = "success"

    FAILED = "failed"

    TIMEOUT = "timeout"

    RATE_LIMITED = "rate_limited"

    CIRCUIT_OPEN = "circuit_open"



@dataclass
class EngineResult:

    engine: str

    status: EngineStatus

    findings: list[dict] = field(
        default_factory=list
    )

    error: str = ""

    metadata: dict = field(
        default_factory=dict
    )