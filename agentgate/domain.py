from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Iterable, Mapping


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    BLOCKER = "blocker"


class FindingState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    FIXED = "fixed"
    VERIFIED = "verified"
    WAIVED = "waived"


class DocumentKind(str, Enum):
    MANIFEST = "manifest"
    IDENTITIES = "identities"
    DESCRIPTIONS = "descriptions"
    DISCOVERY = "discovery"
    INTERACTIONS = "interactions"
    TOOLS = "tools"
    OTA_PLAN = "ota_plan"
    DECLARATIONS = "declarations"
    EVIDENCE = "evidence"
    BASELINE = "baseline"
    CLOSURES = "closures"


class PermissionLevel(int, Enum):
    PUBLIC = 0
    DEVICE = 10
    USER_DATA = 20
    ACCOUNT = 30
    SYSTEM = 40
    PRIVILEGED = 50

    @classmethod
    def parse(cls, value: object) -> "PermissionLevel":
        if isinstance(value, int):
            for member in cls:
                if member.value == value:
                    return member
        if isinstance(value, str):
            normalized = value.strip().replace("-", "_").upper()
            if normalized in cls.__members__:
                return cls[normalized]
        raise ValueError(f"invalid permission level: {value!r}")


class Decision(str, Enum):
    ACCEPT = "accept"
    RETURN = "return"
    MANUAL_REVIEW = "manual_review"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(sorted((str(key), freeze(item)) for key, item in value.items()))
    if isinstance(value, (list, tuple, set, frozenset)):
        return tuple(freeze(item) for item in value)
    return value


@dataclass(frozen=True)
class SourceLocation:
    document: str
    pointer: str = "/"
    line: int | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"document": self.document, "pointer": self.pointer}
        if self.line is not None:
            result["line"] = self.line
        return result


@dataclass(frozen=True)
class Reference:
    source_document: str
    source_pointer: str
    target_kind: str
    target_id: str
    relation: str
    required: bool = True

    @property
    def key(self) -> tuple[str, str]:
        return self.target_kind, self.target_id


@dataclass
class Document:
    name: str
    kind: DocumentKind
    version: str
    data: dict[str, Any]
    digest: str
    path: Path
    references: list[Reference] = field(default_factory=list)

    def identifier_items(self) -> Iterable[tuple[str, str, Mapping[str, Any]]]:
        collection = self.data.get("items")
        if not isinstance(collection, list):
            return []
        result: list[tuple[str, str, Mapping[str, Any]]] = []
        for item in collection:
            if not isinstance(item, Mapping):
                continue
            identity = item.get("id")
            if isinstance(identity, str) and identity:
                result.append((self.kind.value, identity, item))
        return result


@dataclass(frozen=True)
class Capability:
    capability_id: str
    agent_id: str
    category: str
    operation: str
    permission: PermissionLevel
    approval_required: bool
    audit_required: bool
    declared_tools: tuple[str, ...]
    declared_evidence: tuple[str, ...]
    source: SourceLocation

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], source: SourceLocation) -> "Capability":
        return cls(
            capability_id=str(value.get("id", "")),
            agent_id=str(value.get("agent_id", "")),
            category=str(value.get("category", "")),
            operation=str(value.get("operation", "")),
            permission=PermissionLevel.parse(value.get("permission", "public")),
            approval_required=bool(value.get("approval_required", False)),
            audit_required=bool(value.get("audit_required", False)),
            declared_tools=tuple(str(item) for item in value.get("tool_ids", []) if item),
            declared_evidence=tuple(str(item) for item in value.get("evidence_ids", []) if item),
            source=source,
        )


@dataclass(frozen=True)
class ToolGrant:
    tool_id: str
    agent_id: str
    operation: str
    maximum_permission: PermissionLevel
    requires_confirmation: bool
    writes_audit_record: bool
    declaration_ids: tuple[str, ...]
    source: SourceLocation

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], source: SourceLocation) -> "ToolGrant":
        return cls(
            tool_id=str(value.get("id", "")),
            agent_id=str(value.get("agent_id", "")),
            operation=str(value.get("operation", "")),
            maximum_permission=PermissionLevel.parse(value.get("maximum_permission", "public")),
            requires_confirmation=bool(value.get("requires_confirmation", False)),
            writes_audit_record=bool(value.get("writes_audit_record", False)),
            declaration_ids=tuple(str(item) for item in value.get("declaration_ids", []) if item),
            source=source,
        )


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    evidence_type: str
    subject_kind: str
    subject_id: str
    assertion: str
    result: str
    artifact_digest: str
    executed_at: str
    source: SourceLocation

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any], source: SourceLocation) -> "EvidenceRecord":
        return cls(
            evidence_id=str(value.get("id", "")),
            evidence_type=str(value.get("type", "")),
            subject_kind=str(value.get("subject_kind", "")),
            subject_id=str(value.get("subject_id", "")),
            assertion=str(value.get("assertion", "")),
            result=str(value.get("result", "")),
            artifact_digest=str(value.get("artifact_digest", "")),
            executed_at=str(value.get("executed_at", "")),
            source=source,
        )


@dataclass
class Finding:
    code: str
    severity: Severity
    message: str
    location: SourceLocation
    subject: str = ""
    details: dict[str, Any] = field(default_factory=dict)
    fingerprint: str = ""
    state: FindingState = FindingState.OPEN
    first_seen_revision: str = ""
    last_seen_revision: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "severity": self.severity.value,
            "message": self.message,
            "location": self.location.as_dict(),
            "subject": self.subject,
            "details": self.details,
            "fingerprint": self.fingerprint,
            "state": self.state.value,
            "first_seen_revision": self.first_seen_revision,
            "last_seen_revision": self.last_seen_revision,
        }


@dataclass(frozen=True)
class ClosureAction:
    fingerprint: str
    action: str
    operator: str
    reason: str
    evidence_ids: tuple[str, ...]
    recorded_at: str


@dataclass
class Bundle:
    root: Path
    bundle_id: str
    revision: str
    schema_version: str
    submitted_at: str
    documents: dict[DocumentKind, Document]
    raw_manifest: dict[str, Any]

    def get(self, kind: DocumentKind) -> Document | None:
        return self.documents.get(kind)

    def require(self, kind: DocumentKind) -> Document:
        document = self.get(kind)
        if document is None:
            raise KeyError(kind.value)
        return document

    def all_documents(self) -> list[Document]:
        return [self.documents[key] for key in sorted(self.documents, key=lambda item: item.value)]


@dataclass
class ValidationContext:
    bundle: Bundle
    findings: list[Finding] = field(default_factory=list)
    indexes: dict[str, dict[str, Any]] = field(default_factory=dict)
    metrics: dict[str, int | float | str] = field(default_factory=dict)
    artifacts: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def extend(self, findings: Iterable[Finding]) -> None:
        self.findings.extend(findings)

    def count(self, severity: Severity | None = None) -> int:
        if severity is None:
            return len(self.findings)
        return sum(item.severity is severity for item in self.findings)

    def decision(self) -> Decision:
        if any(item.severity in {Severity.ERROR, Severity.BLOCKER} and item.state not in {FindingState.VERIFIED, FindingState.WAIVED} for item in self.findings):
            return Decision.RETURN
        if any(item.severity is Severity.WARNING and item.state is FindingState.OPEN for item in self.findings):
            return Decision.MANUAL_REVIEW
        return Decision.ACCEPT


@dataclass(frozen=True)
class CompilationResult:
    bundle_id: str
    revision: str
    decision: Decision
    findings: tuple[Finding, ...]
    metrics: Mapping[str, Any]
    return_list: Mapping[str, Any]
    review_package: Mapping[str, Any]
    remediation_plan: Mapping[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "bundle_id": self.bundle_id,
            "revision": self.revision,
            "decision": self.decision.value,
            "findings": [item.as_dict() for item in self.findings],
            "metrics": dict(self.metrics),
            "return_list": dict(self.return_list),
            "review_package": dict(self.review_package),
            "remediation_plan": dict(self.remediation_plan),
        }
