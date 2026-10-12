from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from . import knowledge, vrt


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    FIRM = "firm"
    TENTATIVE = "tentative"


@dataclass(frozen=True)
class Asset:
    url: str = ""
    host: str = ""
    ip: str = ""
    port: int | None = None
    scheme: str = ""

    def label(self) -> str:
        if self.url:
            return self.url
        if self.host and self.ip:
            return f"{self.host} ({self.ip})"
        return self.host or self.ip


@dataclass
class Finding:
    module: str
    vrt_id: str
    title: str
    asset: Asset
    evidence: str = ""
    confidence: Confidence = Confidence.FIRM
    request: str = ""
    response_excerpt: str = ""
    remediation: str = ""
    description: str = ""
    business_impact: str = ""
    steps: list[str] = field(default_factory=list)
    target_category: str = "Web App"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def description_text(self) -> str:
        return self.description or knowledge.description(self.vrt_id)

    @property
    def impact_text(self) -> str:
        return self.business_impact or knowledge.business_impact(self.vrt_id)

    @property
    def steps_list(self) -> list[str]:
        if self.steps:
            return self.steps
        generated = []
        if self.asset.url:
            generated.append(f"Navigate to: {self.asset.url}")
        if self.request:
            generated.append(f"Issue the request: {self.request}")
        if self.evidence:
            generated.append(f"Observe the result: {self.evidence}")
        return generated or ["Reproduce the condition described in the evidence."]

    @property
    def priority(self) -> int | None:
        return vrt.priority(self.vrt_id)

    @property
    def priority_label(self) -> str | None:
        return vrt.label(self.vrt_id)

    @property
    def dedupe_key(self) -> tuple[str, str, str]:
        return (self.vrt_id, self.asset.label(), self.evidence[:120])

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["confidence"] = self.confidence.value
        data["priority"] = self.priority
        data["priority_label"] = self.priority_label
        data["vrt_name"] = vrt.name(self.vrt_id)
        data["vrt_chain"] = vrt.readable_chain(self.vrt_id)
        data["description"] = self.description_text
        data["business_impact"] = self.impact_text
        data["steps"] = self.steps_list
        return data
