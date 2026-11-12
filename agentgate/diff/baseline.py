from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from ..domain import DocumentKind, Finding, PermissionLevel, Severity, SourceLocation, ValidationContext, freeze


@dataclass(frozen=True)
class Change:
    kind: str
    subject_id: str
    change_type: str
    risk: str
    changed_fields: tuple[str, ...]
    before_fingerprint: str
    after_fingerprint: str
    before: Mapping[str, Any] | None
    after: Mapping[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "subject_id": self.subject_id,
            "change_type": self.change_type,
            "risk": self.risk,
            "changed_fields": list(self.changed_fields),
            "before_fingerprint": self.before_fingerprint,
            "after_fingerprint": self.after_fingerprint,
        }


class BaselineDiffer:
    high_risk_fields = {
        "permission",
        "maximum_permission",
        "approval_required",
        "requires_confirmation",
        "audit_required",
        "writes_audit_record",
        "tool_ids",
        "data_destinations",
        "consent",
        "unique_code",
    }
    medium_risk_fields = {
        "operation",
        "category",
        "audiences",
        "discoverable",
        "declaration_ids",
        "evidence_ids",
        "from_version",
        "to_version",
    }

    def compare(self, context: ValidationContext) -> list[Change]:
        baseline_document = context.bundle.get(DocumentKind.BASELINE)
        baseline = self._baseline_items(baseline_document.data if baseline_document else {})
        current = self._current_items(context)
        changes: list[Change] = []
        all_keys = sorted(set(baseline) | set(current))
        for key in all_keys:
            before = baseline.get(key)
            after = current.get(key)
            if before is None and after is not None:
                change_type = "added"
                fields = tuple(sorted(after))
            elif before is not None and after is None:
                change_type = "removed"
                fields = tuple(sorted(before))
            elif freeze(before) != freeze(after):
                change_type = "modified"
                fields = self._changed_fields(before or {}, after or {})
            else:
                continue
            risk = self._risk(key[0], change_type, fields, before, after)
            change = Change(
                kind=key[0],
                subject_id=key[1],
                change_type=change_type,
                risk=risk,
                changed_fields=fields,
                before_fingerprint=self._fingerprint(before),
                after_fingerprint=self._fingerprint(after),
                before=before,
                after=after,
            )
            changes.append(change)
            self._emit_finding(change, context)
        self._check_ota_alignment(changes, context)
        self._check_unique_code_stability(changes, context)
        context.artifacts["baseline_diff"] = [item.as_dict() for item in changes]
        context.metrics["baseline_changes"] = len(changes)
        context.metrics["high_risk_changes"] = sum(item.risk == "high" for item in changes)
        return changes

    def snapshot(self, context: ValidationContext) -> dict[str, Any]:
        items = []
        for (kind, identifier), value in sorted(self._current_items(context).items()):
            items.append({
                "id": f"{kind}:{identifier}",
                "kind": kind,
                "subject_id": identifier,
                "fingerprint": self._fingerprint(value),
                "snapshot": value,
            })
        return {"schema_version": context.bundle.schema_version, "items": items}

    def _baseline_items(self, data: Mapping[str, Any]) -> dict[tuple[str, str], Mapping[str, Any]]:
        output: dict[tuple[str, str], Mapping[str, Any]] = {}
        items = data.get("items", [])
        if not isinstance(items, list):
            return output
        for item in items:
            if not isinstance(item, Mapping):
                continue
            kind = item.get("kind")
            subject_id = item.get("subject_id")
            snapshot = item.get("snapshot")
            if isinstance(kind, str) and isinstance(subject_id, str) and isinstance(snapshot, Mapping):
                output[(kind, subject_id)] = dict(snapshot)
        return output

    def _current_items(self, context: ValidationContext) -> dict[tuple[str, str], Mapping[str, Any]]:
        output: dict[tuple[str, str], Mapping[str, Any]] = {}
        excluded = {DocumentKind.BASELINE, DocumentKind.CLOSURES, DocumentKind.EVIDENCE}
        for document in context.bundle.all_documents():
            if document.kind in excluded:
                continue
            items = document.data.get("items", [])
            if not isinstance(items, list):
                continue
            for item in items:
                if isinstance(item, Mapping) and isinstance(item.get("id"), str):
                    output[(document.kind.value, item["id"])] = dict(item)
        return output

    def _changed_fields(self, before: Mapping[str, Any], after: Mapping[str, Any]) -> tuple[str, ...]:
        fields = []
        for key in sorted(set(before) | set(after)):
            if freeze(before.get(key)) != freeze(after.get(key)):
                fields.append(key)
        return tuple(fields)

    def _risk(
        self,
        kind: str,
        change_type: str,
        fields: tuple[str, ...],
        before: Mapping[str, Any] | None,
        after: Mapping[str, Any] | None,
    ) -> str:
        if change_type == "removed" and kind in {DocumentKind.IDENTITIES.value, DocumentKind.DECLARATIONS.value, DocumentKind.TOOLS.value}:
            return "high"
        if self.high_risk_fields.intersection(fields):
            return "high"
        if kind == DocumentKind.INTERACTIONS.value and after is not None:
            try:
                permission = PermissionLevel.parse(after.get("permission", "public"))
            except ValueError:
                permission = PermissionLevel.PRIVILEGED
            if permission.value >= PermissionLevel.USER_DATA.value:
                return "high"
        if change_type in {"added", "removed"} or self.medium_risk_fields.intersection(fields):
            return "medium"
        return "low"

    def _emit_finding(self, change: Change, context: ValidationContext) -> None:
        if change.risk == "high":
            severity = Severity.ERROR
            code = "DIFF_HIGH_RISK_CHANGE"
        elif change.risk == "medium":
            severity = Severity.WARNING
            code = "DIFF_REVIEW_REQUIRED"
        else:
            return
        context.add(Finding(
            code,
            severity,
            f"{change.risk}-risk baseline change requires review",
            SourceLocation("baseline.json", "/items"),
            subject=f"{change.kind}:{change.subject_id}",
            details=change.as_dict(),
        ))

    def _check_ota_alignment(self, changes: list[Change], context: ValidationContext) -> None:
        material = [item for item in changes if item.risk in {"high", "medium"} and item.kind != DocumentKind.OTA_PLAN.value]
        if not material:
            return
        ota = context.bundle.get(DocumentKind.OTA_PLAN)
        if ota is None or not isinstance(ota.data.get("items"), list) or not ota.data["items"]:
            context.add(Finding("DIFF_OTA_PLAN_MISSING", Severity.BLOCKER, "material baseline changes have no OTA plan", SourceLocation("manifest.json", "/documents"), details={"changes": [item.as_dict() for item in material]}))
            return
        covered_kinds: set[str] = set()
        for item in ota.data["items"]:
            if isinstance(item, Mapping):
                assessment = item.get("impact_assessment", {})
                if isinstance(assessment, Mapping):
                    for field, value in assessment.items():
                        if value not in (None, "", [], {}, False):
                            covered_kinds.add(str(field))
        expected = {self._assessment_category(item.kind) for item in material}
        missing = sorted(expected - covered_kinds)
        if missing:
            context.add(Finding("DIFF_OTA_IMPACT_GAP", Severity.ERROR, "OTA impact assessment does not cover all material changes", SourceLocation(ota.name, "/items"), details={"missing_categories": missing}))

    def _assessment_category(self, kind: str) -> str:
        mapping = {
            DocumentKind.IDENTITIES.value: "identity",
            DocumentKind.INTERACTIONS.value: "capabilities",
            DocumentKind.TOOLS.value: "permissions",
            DocumentKind.DECLARATIONS.value: "permissions",
            DocumentKind.DESCRIPTIONS.value: "capabilities",
            DocumentKind.DISCOVERY.value: "capabilities",
        }
        return mapping.get(kind, kind)

    def _check_unique_code_stability(self, changes: list[Change], context: ValidationContext) -> None:
        for change in changes:
            if change.kind != DocumentKind.IDENTITIES.value or "unique_code" not in change.changed_fields:
                continue
            context.add(Finding("DIFF_UNIQUE_CODE_CHANGED", Severity.BLOCKER, "agent unique identity code changed from baseline", SourceLocation("identities.json", "/items"), subject=change.subject_id, details={"before": change.before.get("unique_code") if change.before else None, "after": change.after.get("unique_code") if change.after else None}))

    def _fingerprint(self, value: Mapping[str, Any] | None) -> str:
        if value is None:
            return ""
        payload = json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
