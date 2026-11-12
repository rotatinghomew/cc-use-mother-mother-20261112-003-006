from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Mapping

from ..domain import Document, DocumentKind, Finding, Severity, SourceLocation, ValidationContext
from ..errors import SchemaDefinitionError


Validator = Callable[[Any], bool]


@dataclass(frozen=True)
class FieldRule:
    name: str
    types: tuple[type, ...]
    required: bool = True
    non_empty: bool = False
    pattern: str = ""
    choices: tuple[Any, ...] = ()

    def validate(self, value: Any) -> str | None:
        if not isinstance(value, self.types):
            expected = ",".join(item.__name__ for item in self.types)
            return f"expected {expected}"
        if self.non_empty and hasattr(value, "__len__") and len(value) == 0:
            return "must not be empty"
        if self.pattern and isinstance(value, str) and re.fullmatch(self.pattern, value) is None:
            return "does not match required format"
        if self.choices and value not in self.choices:
            return f"must be one of {self.choices!r}"
        return None


@dataclass(frozen=True)
class ItemSchema:
    fields: tuple[FieldRule, ...]
    allow_extra: bool = True
    validators: tuple[tuple[str, Validator, str], ...] = ()


@dataclass(frozen=True)
class DocumentSchema:
    kind: DocumentKind
    version: str
    root_fields: tuple[FieldRule, ...]
    item_schema: ItemSchema | None = None
    minimum_items: int = 0
    required_document: bool = True
    aliases: tuple[str, ...] = ()


class SchemaRegistry:
    supported_versions = ("1.0", "1.1", "2.0")

    def __init__(self) -> None:
        self.schemas: dict[tuple[str, DocumentKind], DocumentSchema] = {}
        self._install_defaults()

    def register(self, schema: DocumentSchema) -> None:
        key = (schema.version, schema.kind)
        if key in self.schemas:
            raise SchemaDefinitionError("duplicate schema registration", context={"version": schema.version, "kind": schema.kind.value})
        self.schemas[key] = schema

    def validate_bundle(self, context: ValidationContext) -> None:
        version = context.bundle.schema_version
        if version not in self.supported_versions:
            context.add(
                Finding(
                    "SCHEMA_VERSION_UNSUPPORTED",
                    Severity.BLOCKER,
                    f"bundle schema version {version} is unsupported",
                    SourceLocation("manifest.json", "/schema_version"),
                    details={"supported": list(self.supported_versions)},
                )
            )
            return
        required = {schema.kind for (candidate, _), schema in self.schemas.items() if candidate == version and schema.required_document}
        for kind in sorted(required, key=lambda item: item.value):
            if kind not in context.bundle.documents:
                context.add(
                    Finding(
                        "SCHEMA_DOCUMENT_MISSING",
                        Severity.BLOCKER,
                        f"required document {kind.value} is missing",
                        SourceLocation("manifest.json", "/documents"),
                        subject=kind.value,
                    )
                )
        for document in context.bundle.all_documents():
            schema = self.schemas.get((version, document.kind))
            if schema is None:
                context.add(
                    Finding(
                        "SCHEMA_KIND_UNSUPPORTED",
                        Severity.ERROR,
                        f"document kind {document.kind.value} is not supported by version {version}",
                        SourceLocation(document.name, "/"),
                    )
                )
                continue
            self._validate_document(document, schema, context)

    def _validate_document(self, document: Document, schema: DocumentSchema, context: ValidationContext) -> None:
        self._validate_fields(document, document.data, schema.root_fields, "", context)
        items = document.data.get("items")
        if schema.item_schema is not None:
            if not isinstance(items, list):
                context.add(self._finding(document, "/items", "SCHEMA_ITEMS_TYPE", "items must be an array"))
                return
            if len(items) < schema.minimum_items:
                context.add(
                    self._finding(
                        document,
                        "/items",
                        "SCHEMA_ITEMS_MINIMUM",
                        f"at least {schema.minimum_items} item(s) are required",
                        details={"actual": len(items)},
                    )
                )
            seen: set[str] = set()
            for index, item in enumerate(items):
                pointer = f"/items/{index}"
                if not isinstance(item, Mapping):
                    context.add(self._finding(document, pointer, "SCHEMA_ITEM_TYPE", "item must be an object"))
                    continue
                self._validate_fields(document, item, schema.item_schema.fields, pointer, context)
                identifier = item.get("id")
                if isinstance(identifier, str):
                    if identifier in seen:
                        context.add(self._finding(document, pointer + "/id", "SCHEMA_DUPLICATE_ID", "identifier is duplicated", subject=identifier))
                    seen.add(identifier)
                if not schema.item_schema.allow_extra:
                    permitted = {rule.name for rule in schema.item_schema.fields}
                    for key in sorted(set(item) - permitted):
                        context.add(self._finding(document, pointer + f"/{key}", "SCHEMA_EXTRA_FIELD", "field is not allowed", severity=Severity.WARNING))
                for field, validator, message in schema.item_schema.validators:
                    if field in item and not validator(item[field]):
                        context.add(self._finding(document, pointer + f"/{field}", "SCHEMA_CUSTOM_RULE", message, subject=str(identifier or "")))

    def _validate_fields(
        self,
        document: Document,
        value: Mapping[str, Any],
        rules: tuple[FieldRule, ...],
        pointer: str,
        context: ValidationContext,
    ) -> None:
        for rule in rules:
            child = f"{pointer}/{rule.name}"
            if rule.name not in value:
                if rule.required:
                    context.add(self._finding(document, child, "SCHEMA_REQUIRED_FIELD", "required field is missing"))
                continue
            problem = rule.validate(value[rule.name])
            if problem:
                context.add(self._finding(document, child, "SCHEMA_FIELD_INVALID", problem))

    def _finding(
        self,
        document: Document,
        pointer: str,
        code: str,
        message: str,
        *,
        subject: str = "",
        severity: Severity = Severity.ERROR,
        details: dict[str, Any] | None = None,
    ) -> Finding:
        return Finding(code, severity, message, SourceLocation(document.name, pointer), subject=subject, details=details or {})

    def _install_defaults(self) -> None:
        root = (
            FieldRule("schema_version", (str,), non_empty=True),
            FieldRule("items", (list,)),
        )
        common_id = FieldRule("id", (str,), non_empty=True, pattern=r"[A-Za-z0-9][A-Za-z0-9._:-]{1,127}")
        digest = FieldRule("artifact_digest", (str,), pattern=r"[0-9a-f]{64}")
        iso_time = lambda value: self._is_datetime(value)
        versions = self.supported_versions
        for version in versions:
            self.register(DocumentSchema(DocumentKind.IDENTITIES, version, root, ItemSchema((
                common_id,
                FieldRule("unique_code", (str,), non_empty=True, pattern=r"AGT-[A-Z0-9]{8,32}"),
                FieldRule("vendor", (str,), non_empty=True),
                FieldRule("product", (str,), non_empty=True),
                FieldRule("status", (str,), choices=("active", "suspended", "retired")),
            )), 1))
            self.register(DocumentSchema(DocumentKind.DESCRIPTIONS, version, root, ItemSchema((
                common_id, FieldRule("agent_id", (str,), non_empty=True), FieldRule("display_name", (str,), non_empty=True),
                FieldRule("purpose", (str,), non_empty=True), FieldRule("owner", (str,), non_empty=True),
                FieldRule("data_destinations", (list,), non_empty=True),
            )), 1))
            self.register(DocumentSchema(DocumentKind.DISCOVERY, version, root, ItemSchema((
                common_id, FieldRule("agent_id", (str,), non_empty=True), FieldRule("channel", (str,), non_empty=True),
                FieldRule("discoverable", (bool,)), FieldRule("audiences", (list,), non_empty=True),
            )), 1))
            self.register(DocumentSchema(DocumentKind.INTERACTIONS, version, root, ItemSchema((
                common_id, FieldRule("agent_id", (str,), non_empty=True), FieldRule("operation", (str,), non_empty=True),
                FieldRule("category", (str,), choices=("discovery", "interaction", "tool_call")),
                FieldRule("permission", (str, int)), FieldRule("approval_required", (bool,)),
                FieldRule("audit_required", (bool,)), FieldRule("tool_ids", (list,)), FieldRule("evidence_ids", (list,)),
            )), 1))
            self.register(DocumentSchema(DocumentKind.TOOLS, version, root, ItemSchema((
                common_id, FieldRule("agent_id", (str,), non_empty=True), FieldRule("operation", (str,), non_empty=True),
                FieldRule("maximum_permission", (str, int)), FieldRule("requires_confirmation", (bool,)),
                FieldRule("writes_audit_record", (bool,)), FieldRule("declaration_ids", (list,)),
            )), 1))
            self.register(DocumentSchema(DocumentKind.OTA_PLAN, version, root, ItemSchema((
                common_id, FieldRule("agent_id", (str,), non_empty=True), FieldRule("from_version", (str,), non_empty=True),
                FieldRule("to_version", (str,), non_empty=True), FieldRule("scheme_submitted", (bool,)),
                FieldRule("completion_report_required", (bool,)), FieldRule("impact_assessment", (dict,), non_empty=True),
                FieldRule("evidence_ids", (list,), non_empty=True),
            )), 1))
            self.register(DocumentSchema(DocumentKind.DECLARATIONS, version, root, ItemSchema((
                common_id, FieldRule("application_id", (str,), non_empty=True), FieldRule("agent_id", (str,), non_empty=True),
                FieldRule("tool_ids", (list,), non_empty=True), FieldRule("consent", (bool,)),
                FieldRule("signature_algorithm", (str,), choices=("hmac-sha256",)),
                FieldRule("signer", (str,), non_empty=True), FieldRule("payload_digest", (str,), pattern=r"[0-9a-f]{64}"),
                FieldRule("signature", (str,), pattern=r"[0-9a-f]{64}"),
            )), 1))
            self.register(DocumentSchema(DocumentKind.EVIDENCE, version, root, ItemSchema((
                common_id, FieldRule("type", (str,), non_empty=True), FieldRule("subject_kind", (str,), non_empty=True),
                FieldRule("subject_id", (str,), non_empty=True), FieldRule("assertion", (str,), non_empty=True),
                FieldRule("result", (str,), choices=("pass", "fail", "inconclusive")), digest,
                FieldRule("executed_at", (str,), non_empty=True),
            ), validators=(("executed_at", iso_time, "executed_at must be ISO-8601"),)), 1))
            self.register(DocumentSchema(DocumentKind.BASELINE, version, root, ItemSchema((
                common_id, FieldRule("kind", (str,), non_empty=True), FieldRule("subject_id", (str,), non_empty=True),
                FieldRule("fingerprint", (str,), pattern=r"[0-9a-f]{64}"), FieldRule("snapshot", (dict,), non_empty=True),
            )), 0, required_document=False))
            self.register(DocumentSchema(DocumentKind.CLOSURES, version, root, ItemSchema((
                common_id, FieldRule("finding_fingerprint", (str,), pattern=r"[0-9a-f]{64}"),
                FieldRule("action", (str,), choices=("acknowledge", "fix", "verify", "waive")),
                FieldRule("operator", (str,), non_empty=True), FieldRule("reason", (str,), non_empty=True),
                FieldRule("evidence_ids", (list,)), FieldRule("recorded_at", (str,), non_empty=True),
            ), validators=(("recorded_at", iso_time, "recorded_at must be ISO-8601"),)), 0, required_document=False))

    def _is_datetime(self, value: object) -> bool:
        if not isinstance(value, str):
            return False
        try:
            datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return False
        return True
