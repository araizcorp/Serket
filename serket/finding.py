"""Versioned, JSON-safe finding schema for Serket risk inference."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from hashlib import sha256
from typing import Any, Optional


FINDING_SCHEMA = "finding://serket/v1"
RISK_MODEL = "serket-risk/v1"


def stable_token(*parts: Any, length: int = 24) -> str:
    """Hash stable identifiers without leaking their raw concatenation."""
    raw = "\x1f".join(str(part or "") for part in parts).encode("utf-8")
    return sha256(raw).hexdigest()[:length]


@dataclass(frozen=True)
class Evidence:
    type: str
    source: str
    value: Any
    interpretation: str


@dataclass(frozen=True)
class EdgeRef:
    id: str
    source: str
    target: str
    relation: str
    cost: float
    mitre: Optional[str] = None


@dataclass
class AttackPath:
    path_id: str
    edges: list[EdgeRef] = field(default_factory=list)
    cost: float = 0
    technique_chain: list[str] = field(default_factory=list)
    is_cheapest: bool = False


@dataclass(frozen=True)
class RiskComponents:
    impact: int = 0
    reachability: int = 0
    exploitability: int = 0
    exposure: int = 0

    @property
    def total(self) -> int:
        return max(0, min(100, sum((
            self.impact, self.reachability,
            self.exploitability, self.exposure,
        ))))


@dataclass
class Finding:
    id: str
    snapshot_id: str
    object_id: str
    object_type: str
    badge: str
    category: str
    severity: str
    confidence: str
    certainty: str
    evidence: list[Evidence] = field(default_factory=list)
    paths: list[AttackPath] = field(default_factory=list)
    tier0_reachable: bool = False
    tier0_distance: Optional[int] = None
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    risk_model: str = RISK_MODEL
    risk_score: int = 0
    risk_components: RiskComponents = field(default_factory=RiskComponents)
    created_at: str = ""
    remediation: Optional[str] = None

    @classmethod
    def create(cls, *, snapshot_id: str, object_id: str, technique: str,
               index: int = 0, stable_object_id: str | None = None,
               **kwargs) -> "Finding":
        locator = stable_token(
            snapshot_id, stable_object_id or object_id, technique, index
        )
        return cls(
            id=f"{FINDING_SCHEMA}/{snapshot_id}/{locator}",
            snapshot_id=snapshot_id,
            object_id=object_id,
            **kwargs,
        )

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["risk_score"] = self.risk_components.total
        return payload
