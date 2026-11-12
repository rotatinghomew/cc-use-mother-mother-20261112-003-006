from __future__ import annotations

import copy
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..domain import Bundle, Document, DocumentKind, Finding, Severity, SourceLocation, ValidationContext


Migration = Callable[[dict[str, Any]], dict[str, Any]]


@dataclass(frozen=True)
class MigrationStep:
    kind: DocumentKind
    source_version: str
    target_version: str
    transform: Migration
    notes: tuple[str, ...] = ()


@dataclass
class NormalizationLog:
    document: str
    source_version: str
    target_version: str
    changes: list[dict[str, Any]] = field(default_factory=list)

    def add(self, pointer: str, operation: str, before: Any, after: Any) -> None:
        self.changes.append({"pointer": pointer, "operation": operation, "before": before, "after": after})

    def as_dict(self) -> dict[str, Any]:
        return {
            "document": self.document,
            "source_version": self.source_version,
            "target_version": self.target_version,
            "changes": self.changes,
        }


class DocumentNormalizer:
    canonical_version = "2.0"

    def __init__(self) -> None:
        self.migrations: dict[tuple[DocumentKind, str], MigrationStep] = {}
        self._install_migrations()

    def normalize(self, context: ValidationContext) -> None:
        logs: list[NormalizationLog] = []
        for document in context.bundle.all_documents():
            log = self._normalize_document(document, context)
            logs.append(log)
        context.artifacts["normalization"] = [log.as_dict() for log in logs]
        context.metrics["normalized_documents"] = len(logs)
        context.metrics["normalization_changes"] = sum(len(log.changes) for log in logs)

    def _normalize_document(self, document: Document, context: ValidationContext) -> NormalizationLog:
        source_version = document.version
        log = NormalizationLog(document.name, source_version, self.canonical_version)
        data = copy.deepcopy(document.data)
        version = source_version
        visited: set[str] = set()
        while version != self.canonical_version:
            if version in visited:
                context.add(Finding("NORMALIZATION_MIGRATION_CYCLE", Severity.BLOCKER, "schema migration contains a cycle", SourceLocation(document.name, "/schema_version"), details={"version": version}))
                return log
            visited.add(version)
            step = self.migrations.get((document.kind, version))
            if step is None:
                context.add(Finding("NORMALIZATION_PATH_MISSING", Severity.ERROR, "document has no migration path to the canonical schema", SourceLocation(document.name, "/schema_version"), details={"source": version, "target": self.canonical_version, "kind": document.kind.value}))
                return log
            before = copy.deepcopy(data)
            data = step.transform(data)
            self._record_diff(before, data, "", log)
            version = step.target_version
        before_common = copy.deepcopy(data)
        self._common_normalization(document.kind, data)
        self._record_diff(before_common, data, "", log)
        data["schema_version"] = self.canonical_version
        document.data = data
        document.version = self.canonical_version
        return log

    def _common_normalization(self, kind: DocumentKind, data: dict[str, Any]) -> None:
        items = data.get("items")
        if not isinstance(items, list):
            return
        for item in items:
            if not isinstance(item, dict):
                continue
            for key, value in list(item.items()):
                if isinstance(value, str):
                    item[key] = value.strip()
                elif isinstance(value, list):
                    normalized = [entry.strip() if isinstance(entry, str) else entry for entry in value]
                    item[key] = self._stable_unique(normalized)
            if kind is DocumentKind.IDENTITIES and isinstance(item.get("unique_code"), str):
                item["unique_code"] = item["unique_code"].upper()
            if kind in {DocumentKind.INTERACTIONS, DocumentKind.TOOLS}:
                for key in ("permission", "maximum_permission"):
                    if isinstance(item.get(key), str):
                        item[key] = item[key].strip().lower().replace("-", "_")
            if kind is DocumentKind.DECLARATIONS and isinstance(item.get("signature_algorithm"), str):
                item["signature_algorithm"] = item["signature_algorithm"].lower()
            if kind is DocumentKind.EVIDENCE:
                for key in ("type", "subject_kind", "assertion", "result"):
                    if isinstance(item.get(key), str):
                        item[key] = item[key].strip().lower()

    def _stable_unique(self, values: list[Any]) -> list[Any]:
        output: list[Any] = []
        seen: set[str] = set()
        for value in values:
            marker = repr(value)
            if marker in seen:
                continue
            seen.add(marker)
            output.append(value)
        return output

    def _record_diff(self, before: Any, after: Any, pointer: str, log: NormalizationLog) -> None:
        if type(before) is not type(after):
            log.add(pointer or "/", "replace", before, after)
            return
        if isinstance(before, Mapping):
            for key in sorted(set(before) | set(after)):
                child = f"{pointer}/{self._escape(str(key))}"
                if key not in before:
                    log.add(child, "add", None, after[key])
                elif key not in after:
                    log.add(child, "remove", before[key], None)
                else:
                    self._record_diff(before[key], after[key], child, log)
            return
        if isinstance(before, list):
            if before != after:
                log.add(pointer or "/", "replace", before, after)
            return
        if before != after:
            log.add(pointer or "/", "replace", before, after)

    def _escape(self, value: str) -> str:
        return value.replace("~", "~0").replace("/", "~1")

    def _install_migrations(self) -> None:
        for kind in DocumentKind:
            if kind is DocumentKind.MANIFEST:
                continue
            self._register(MigrationStep(kind, "1.0", "1.1", self._migration_10_to_11(kind)))
            self._register(MigrationStep(kind, "1.1", "2.0", self._migration_11_to_20(kind)))

    def _register(self, step: MigrationStep) -> None:
        self.migrations[(step.kind, step.source_version)] = step

    def _migration_10_to_11(self, kind: DocumentKind) -> Migration:
        def transform(data: dict[str, Any]) -> dict[str, Any]:
            result = copy.deepcopy(data)
            result["schema_version"] = "1.1"
            items = result.get("items", [])
            if not isinstance(items, list):
                return result
            for item in items:
                if not isinstance(item, dict):
                    continue
                if kind is DocumentKind.IDENTITIES:
                    self._rename(item, "identity_code", "unique_code")
                    item.setdefault("status", "active")
                elif kind is DocumentKind.DESCRIPTIONS:
                    self._rename(item, "name", "display_name")
                    item.setdefault("data_destinations", ["local-device"])
                elif kind is DocumentKind.DISCOVERY:
                    self._rename(item, "scope", "audiences")
                    if isinstance(item.get("audiences"), str):
                        item["audiences"] = [item["audiences"]]
                    item.setdefault("discoverable", True)
                elif kind is DocumentKind.INTERACTIONS:
                    self._rename(item, "requires_approval", "approval_required")
                    self._rename(item, "requires_audit", "audit_required")
                    item.setdefault("tool_ids", [])
                    item.setdefault("evidence_ids", [])
                elif kind is DocumentKind.TOOLS:
                    self._rename(item, "permission", "maximum_permission")
                    self._rename(item, "confirmation", "requires_confirmation")
                    self._rename(item, "audit", "writes_audit_record")
                    item.setdefault("declaration_ids", [])
                elif kind is DocumentKind.OTA_PLAN:
                    self._rename(item, "submitted", "scheme_submitted")
                    item.setdefault("completion_report_required", True)
                    item.setdefault("evidence_ids", [])
                elif kind is DocumentKind.DECLARATIONS:
                    self._rename(item, "app_id", "application_id")
                    item.setdefault("consent", False)
                    item.setdefault("signature_algorithm", "hmac-sha256")
                elif kind is DocumentKind.EVIDENCE:
                    self._rename(item, "digest", "artifact_digest")
                    self._rename(item, "time", "executed_at")
                elif kind is DocumentKind.CLOSURES:
                    self._rename(item, "fingerprint", "finding_fingerprint")
                    item.setdefault("evidence_ids", [])
            return result
        return transform

    def _migration_11_to_20(self, kind: DocumentKind) -> Migration:
        def transform(data: dict[str, Any]) -> dict[str, Any]:
            result = copy.deepcopy(data)
            result["schema_version"] = "2.0"
            items = result.get("items", [])
            if not isinstance(items, list):
                return result
            for item in items:
                if not isinstance(item, dict):
                    continue
                if kind is DocumentKind.INTERACTIONS:
                    item.setdefault("category", "interaction")
                if kind is DocumentKind.OTA_PLAN:
                    assessment = item.setdefault("impact_assessment", {})
                    if isinstance(assessment, dict):
                        assessment.setdefault("identity", "reviewed")
                        assessment.setdefault("capabilities", "reviewed")
                        assessment.setdefault("permissions", "reviewed")
                        assessment.setdefault("evidence", "reviewed")
                        assessment.setdefault("rollback", "defined")
                if kind is DocumentKind.BASELINE:
                    item.setdefault("fingerprint", "0" * 64)
            return result
        return transform

    def _rename(self, item: dict[str, Any], old: str, new: str) -> None:
        if old in item and new not in item:
            item[new] = item.pop(old)
