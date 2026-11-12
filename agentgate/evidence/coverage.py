from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

from ..domain import Capability, DocumentKind, EvidenceRecord, Finding, PermissionLevel, Severity, SourceLocation, ValidationContext


@dataclass(frozen=True)
class CoverageRequirement:
    requirement_id: str
    subject_kind: str
    subject_id: str
    assertion: str
    accepted_types: tuple[str, ...]
    minimum_passes: int
    maximum_age_days: int | None
    severity: Severity

    def as_dict(self) -> dict[str, Any]:
        return {
            "requirement_id": self.requirement_id,
            "subject_kind": self.subject_kind,
            "subject_id": self.subject_id,
            "assertion": self.assertion,
            "accepted_types": list(self.accepted_types),
            "minimum_passes": self.minimum_passes,
            "maximum_age_days": self.maximum_age_days,
            "severity": self.severity.value,
        }


@dataclass(frozen=True)
class CoverageResult:
    requirement: CoverageRequirement
    matched: tuple[str, ...]
    passing: tuple[str, ...]
    stale: tuple[str, ...]
    failing: tuple[str, ...]

    @property
    def covered(self) -> bool:
        return len(self.passing) >= self.requirement.minimum_passes

    def as_dict(self) -> dict[str, Any]:
        value = self.requirement.as_dict()
        value.update(
            matched=list(self.matched),
            passing=list(self.passing),
            stale=list(self.stale),
            failing=list(self.failing),
            covered=self.covered,
        )
        return value


class EvidenceCoverageTracker:
    def track(self, context: ValidationContext) -> list[CoverageResult]:
        evidence = self._records(context)
        requirements = self._requirements(context)
        by_subject: dict[tuple[str, str], list[EvidenceRecord]] = defaultdict(list)
        by_id = {item.evidence_id: item for item in evidence}
        for record in evidence:
            by_subject[(record.subject_kind, record.subject_id)].append(record)
            self._validate_record(record, context)
        results: list[CoverageResult] = []
        for requirement in requirements:
            candidates = by_subject.get((requirement.subject_kind, requirement.subject_id), [])
            matched: list[str] = []
            passing: list[str] = []
            stale: list[str] = []
            failing: list[str] = []
            for record in candidates:
                if record.assertion != requirement.assertion or record.evidence_type not in requirement.accepted_types:
                    continue
                matched.append(record.evidence_id)
                if self._is_stale(record, requirement.maximum_age_days):
                    stale.append(record.evidence_id)
                elif record.result == "pass":
                    passing.append(record.evidence_id)
                else:
                    failing.append(record.evidence_id)
            result = CoverageResult(requirement, tuple(matched), tuple(passing), tuple(stale), tuple(failing))
            results.append(result)
            self._emit_coverage_findings(result, context)
        self._check_declared_ids(context, by_id)
        self._check_duplicate_artifacts(evidence, context)
        self._check_ota_evidence(context, by_id)
        self._check_unbound_evidence(evidence, requirements, context)
        context.artifacts["evidence_coverage"] = [item.as_dict() for item in results]
        context.metrics["evidence_records"] = len(evidence)
        context.metrics["coverage_requirements"] = len(requirements)
        context.metrics["coverage_satisfied"] = sum(item.covered for item in results)
        context.metrics["coverage_ratio"] = round(sum(item.covered for item in results) / len(results), 4) if results else 1.0
        return results

    def _records(self, context: ValidationContext) -> list[EvidenceRecord]:
        document = context.bundle.get(DocumentKind.EVIDENCE)
        if document is None:
            return []
        items = document.data.get("items", [])
        output: list[EvidenceRecord] = []
        if not isinstance(items, list):
            return output
        for index, item in enumerate(items):
            if isinstance(item, Mapping):
                output.append(EvidenceRecord.from_mapping(item, SourceLocation(document.name, f"/items/{index}")))
        return output

    def _requirements(self, context: ValidationContext) -> list[CoverageRequirement]:
        output: list[CoverageRequirement] = []
        capabilities = context.bundle.get(DocumentKind.INTERACTIONS)
        if capabilities is not None:
            items = capabilities.data.get("items", [])
            if isinstance(items, list):
                for index, item in enumerate(items):
                    if not isinstance(item, Mapping):
                        continue
                    try:
                        capability = Capability.from_mapping(item, SourceLocation(capabilities.name, f"/items/{index}"))
                    except ValueError:
                        continue
                    accepted = ("control-test", "integration-test")
                    severity = Severity.BLOCKER if capability.permission.value >= PermissionLevel.SYSTEM.value else Severity.ERROR
                    output.append(CoverageRequirement(
                        f"capability:{capability.capability_id}:authorization",
                        DocumentKind.INTERACTIONS.value,
                        capability.capability_id,
                        "authorization_controls",
                        accepted,
                        1,
                        180,
                        severity,
                    ))
                    if capability.audit_required:
                        output.append(CoverageRequirement(
                            f"capability:{capability.capability_id}:audit",
                            DocumentKind.INTERACTIONS.value,
                            capability.capability_id,
                            "audit_record_created",
                            ("control-test", "log-proof"),
                            1,
                            180,
                            severity,
                        ))
        identities = context.bundle.get(DocumentKind.IDENTITIES)
        if identities is not None and isinstance(identities.data.get("items"), list):
            for item in identities.data["items"]:
                if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                    output.append(CoverageRequirement(
                        f"identity:{item['id']}:unique-code",
                        DocumentKind.IDENTITIES.value,
                        item["id"],
                        "unique_code_registered",
                        ("registry-check", "control-test"),
                        1,
                        365,
                        Severity.ERROR,
                    ))
        declarations = context.bundle.get(DocumentKind.DECLARATIONS)
        if declarations is not None and isinstance(declarations.data.get("items"), list):
            for item in declarations.data["items"]:
                if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                    output.append(CoverageRequirement(
                        f"declaration:{item['id']}:signature",
                        DocumentKind.DECLARATIONS.value,
                        item["id"],
                        "signature_verified",
                        ("signature-check",),
                        1,
                        365,
                        Severity.BLOCKER,
                    ))
        ota = context.bundle.get(DocumentKind.OTA_PLAN)
        if ota is not None and isinstance(ota.data.get("items"), list):
            for item in ota.data["items"]:
                if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                    output.append(CoverageRequirement(
                        f"ota:{item['id']}:impact",
                        DocumentKind.OTA_PLAN.value,
                        item["id"],
                        "impact_assessment_reviewed",
                        ("review-record", "control-test"),
                        1,
                        180,
                        Severity.ERROR,
                    ))
        return output

    def _validate_record(self, record: EvidenceRecord, context: ValidationContext) -> None:
        if not record.artifact_digest or len(record.artifact_digest) != 64:
            context.add(Finding("EVIDENCE_DIGEST_INVALID", Severity.ERROR, "evidence artifact digest is invalid", record.source, subject=record.evidence_id))
        timestamp = self._parse_time(record.executed_at)
        if timestamp is None:
            context.add(Finding("EVIDENCE_TIME_INVALID", Severity.ERROR, "evidence execution time is invalid", record.source, subject=record.evidence_id))
        elif timestamp > datetime.now(timezone.utc):
            context.add(Finding("EVIDENCE_TIME_IN_FUTURE", Severity.ERROR, "evidence execution time is in the future", record.source, subject=record.evidence_id))
        if record.result == "fail":
            context.add(Finding("EVIDENCE_REPORTED_FAILURE", Severity.ERROR, "submitted evidence reports a failed control", record.source, subject=record.evidence_id, details={"assertion": record.assertion}))
        elif record.result == "inconclusive":
            context.add(Finding("EVIDENCE_INCONCLUSIVE", Severity.WARNING, "submitted evidence is inconclusive", record.source, subject=record.evidence_id, details={"assertion": record.assertion}))

    def _emit_coverage_findings(self, result: CoverageResult, context: ValidationContext) -> None:
        requirement = result.requirement
        location = SourceLocation("evidence.json", "/items")
        if not result.matched:
            context.add(Finding("EVIDENCE_COVERAGE_MISSING", requirement.severity, "required evidence assertion is missing", location, subject=requirement.subject_id, details=requirement.as_dict()))
        elif not result.covered:
            context.add(Finding("EVIDENCE_COVERAGE_UNSATISFIED", requirement.severity, "evidence exists but no current passing record satisfies the requirement", location, subject=requirement.subject_id, details={"requirement": requirement.as_dict(), "matched": list(result.matched), "stale": list(result.stale), "failing": list(result.failing)}))
        if result.stale:
            context.add(Finding("EVIDENCE_STALE", Severity.WARNING, "one or more evidence records are stale", location, subject=requirement.subject_id, details={"evidence_ids": list(result.stale)}))

    def _check_declared_ids(self, context: ValidationContext, evidence: Mapping[str, EvidenceRecord]) -> None:
        for kind in (DocumentKind.INTERACTIONS, DocumentKind.OTA_PLAN):
            document = context.bundle.get(kind)
            if document is None or not isinstance(document.data.get("items"), list):
                continue
            for index, item in enumerate(document.data["items"]):
                if not isinstance(item, Mapping):
                    continue
                identifiers = item.get("evidence_ids", [])
                if not isinstance(identifiers, list):
                    continue
                for evidence_id in identifiers:
                    if evidence_id not in evidence:
                        continue
                    record = evidence[evidence_id]
                    if record.subject_id != item.get("id"):
                        context.add(Finding("EVIDENCE_SUBJECT_MISMATCH", Severity.ERROR, "declared evidence belongs to a different subject", SourceLocation(document.name, f"/items/{index}/evidence_ids"), subject=str(item.get("id", "")), details={"evidence_id": evidence_id, "actual_subject": record.subject_id}))

    def _check_duplicate_artifacts(self, evidence: Iterable[EvidenceRecord], context: ValidationContext) -> None:
        by_digest: dict[str, list[EvidenceRecord]] = defaultdict(list)
        for record in evidence:
            by_digest[record.artifact_digest].append(record)
        for digest, group in by_digest.items():
            subjects = {(item.subject_kind, item.subject_id, item.assertion) for item in group}
            if digest and len(subjects) > 1:
                context.add(Finding("EVIDENCE_ARTIFACT_REUSED", Severity.WARNING, "the same artifact is reused for different control assertions", group[0].source, subject=digest, details={"evidence_ids": [item.evidence_id for item in group]}))

    def _check_ota_evidence(self, context: ValidationContext, evidence: Mapping[str, EvidenceRecord]) -> None:
        document = context.bundle.get(DocumentKind.OTA_PLAN)
        if document is None or not isinstance(document.data.get("items"), list):
            return
        for index, item in enumerate(document.data["items"]):
            if not isinstance(item, Mapping):
                continue
            location = SourceLocation(document.name, f"/items/{index}")
            if item.get("scheme_submitted") is not True:
                context.add(Finding("OTA_SCHEME_NOT_SUBMITTED", Severity.BLOCKER, "OTA scheme has not been submitted", location, subject=str(item.get("id", ""))))
            if item.get("completion_report_required") is not True:
                context.add(Finding("OTA_COMPLETION_REPORT_NOT_REQUIRED", Severity.ERROR, "OTA plan does not require a completion report", location, subject=str(item.get("id", ""))))
            assessment = item.get("impact_assessment")
            required = {"identity", "capabilities", "permissions", "evidence", "rollback"}
            if not isinstance(assessment, Mapping):
                continue
            missing = sorted(required - set(assessment))
            if missing:
                context.add(Finding("OTA_ASSESSMENT_INCOMPLETE", Severity.ERROR, "OTA impact assessment is incomplete", location, subject=str(item.get("id", "")), details={"missing": missing}))

    def _check_unbound_evidence(self, evidence: Iterable[EvidenceRecord], requirements: Iterable[CoverageRequirement], context: ValidationContext) -> None:
        subjects = {(item.subject_kind, item.subject_id) for item in requirements}
        for record in evidence:
            if (record.subject_kind, record.subject_id) not in subjects:
                context.add(Finding("EVIDENCE_UNBOUND", Severity.WARNING, "evidence does not satisfy any generated requirement", record.source, subject=record.evidence_id))

    def _is_stale(self, record: EvidenceRecord, maximum_age_days: int | None) -> bool:
        if maximum_age_days is None:
            return False
        timestamp = self._parse_time(record.executed_at)
        if timestamp is None:
            return True
        age = datetime.now(timezone.utc) - timestamp
        return age.days > maximum_age_days

    def _parse_time(self, value: str) -> datetime | None:
        try:
            timestamp = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.astimezone(timezone.utc)
