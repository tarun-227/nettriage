"""Report schema. This is the contract between the engine, the CLI and the UI.

Every string in a Report that came from packet data has already been passed
through ``security.sanitize.display_safe`` before it reaches these models.
"""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, Field

SCHEMA_VERSION = "1"


class Verdict(StrEnum):
    ATTACK = "attack"
    FAULT = "fault"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EvidenceItem(BaseModel):
    """One observed fact and how strongly it pushed one hypothesis."""

    reason: str
    weight: float
    frames: list[int] = Field(default_factory=list)


class Hypothesis(BaseModel):
    key: str
    label: str
    verdict: Verdict
    probability: float
    evidence: list[EvidenceItem] = Field(default_factory=list)


class Entity(BaseModel):
    kind: str  # ip, mac, port, domain, host
    value: str
    role: str | None = None


class KeyPacket(BaseModel):
    frame: int
    ts: float
    src: str
    dst: str
    protocol: str
    summary: str


class Finding(BaseModel):
    id: str
    analyzer: str
    kind: str
    title: str
    verdict: Verdict
    confidence: float
    margin: float
    severity: Severity
    summary_simple: str
    summary_technical: str
    cause: str
    fix_steps: list[str]
    hypotheses: list[Hypothesis]
    entities: list[Entity]
    time_start: float
    time_end: float
    frames: list[int]
    key_packets: list[KeyPacket]
    wireshark_filter: str
    has_evidence_pcap: bool = False


class SkipExample(BaseModel):
    frame: int
    reason: str


class IngestStats(BaseModel):
    format: str
    link_types: list[str]
    packets_total: int = 0
    packets_decoded: int = 0
    packets_skipped: int = 0
    skip_reasons: dict[str, int] = Field(default_factory=dict)
    skip_examples: list[SkipExample] = Field(default_factory=list)
    stopped_early: bool = False
    stop_reason: str | None = None
    state_caps_hit: list[str] = Field(default_factory=list)


class IntegrityCheck(BaseModel):
    name: str
    passed: bool
    detail: str


class CaptureInfo(BaseModel):
    file_name: str
    sha256: str
    size_bytes: int
    first_ts: float | None = None
    last_ts: float | None = None
    duration: float = 0.0


class QualityWarning(BaseModel):
    code: str
    message: str
    detail: str = ""


class TimelineBucket(BaseModel):
    t: float
    packets: int
    bytes: int


class Report(BaseModel):
    schema_version: str = SCHEMA_VERSION
    capture: CaptureInfo
    ingest: IngestStats
    integrity: list[IntegrityCheck] = Field(default_factory=list)
    quality: list[QualityWarning] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    ruled_out: list[Finding] = Field(default_factory=list)
    hosts: int = 0
    protocols: dict[str, int] = Field(default_factory=dict)
    timeline: list[TimelineBucket] = Field(default_factory=list)
    analysis_seconds: float = 0.0
