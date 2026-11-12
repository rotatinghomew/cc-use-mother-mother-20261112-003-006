from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..domain import Document, DocumentKind, Finding, Severity, SourceLocation, ValidationContext


@dataclass(frozen=True)
class CatalogEntry:
    kind: str
    identifier: str
    agent_id: str
    document: str
    pointer: str
    fingerprint: str
    attributes: tuple[str, ...]

    def as_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "id": self.identifier,
            "agent_id": self.agent_id,
            "document": self.document,
            "pointer": self.pointer,
            "fingerprint": self.fingerprint,
            "attributes": list(self.attributes),
        }


class SubmissionCatalog:
    def build(self, context: ValidationContext) -> list[CatalogEntry]:
        entries: list[CatalogEntry] = []
        for document in context.bundle.all_documents():
            entries.extend(self._document_entries(document, context))
        self._check_identifier_namespaces(entries, context)
        self._check_per_agent_inventory(entries, context)
        self._check_document_cardinality(entries, context)
        context.artifacts["submission_catalog"] = [entry.as_dict() for entry in entries]
        context.metrics["catalog_entries"] = len(entries)
        context.metrics["catalog_agents"] = len({entry.agent_id for entry in entries if entry.agent_id})
        return entries

    def _document_entries(self, document: Document, context: ValidationContext) -> list[CatalogEntry]:
        items = document.data.get("items", [])
        if not isinstance(items, list):
            return []
        output: list[CatalogEntry] = []
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                continue
            identifier = item.get("id")
            if not isinstance(identifier, str) or not identifier:
                continue
            agent_id = self._agent_id(document.kind, item)
            fingerprint = self._fingerprint(item)
            attributes = tuple(sorted(str(key) for key in item if key not in {"id", "agent_id"}))
            output.append(CatalogEntry(document.kind.value, identifier, agent_id, document.name, f"/items/{index}", fingerprint, attributes))
            self._check_reserved_identifier(identifier, document.name, index, context)
            self._check_agent_identifier(agent_id, document, index, context)
        return output

    def _agent_id(self, kind: DocumentKind, item: Mapping[str, Any]) -> str:
        if kind is DocumentKind.IDENTITIES:
            return str(item.get("id", ""))
        return str(item.get("agent_id", ""))

    def _fingerprint(self, item: Mapping[str, Any]) -> str:
        payload = json.dumps(item, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _check_reserved_identifier(self, identifier: str, document: str, index: int, context: ValidationContext) -> None:
        lowered = identifier.casefold()
        if lowered.startswith(("test-", "sample-", "example-", "dummy-")):
            context.add(Finding("CATALOG_PLACEHOLDER_ID", Severity.ERROR, "submission identifier uses a placeholder prefix", SourceLocation(document, f"/items/{index}/id"), subject=identifier))
        if identifier != identifier.strip():
            context.add(Finding("CATALOG_ID_WHITESPACE", Severity.ERROR, "submission identifier has surrounding whitespace", SourceLocation(document, f"/items/{index}/id"), subject=identifier))

    def _check_agent_identifier(self, agent_id: str, document: Document, index: int, context: ValidationContext) -> None:
        if document.kind in {DocumentKind.BASELINE, DocumentKind.CLOSURES, DocumentKind.EVIDENCE, DocumentKind.DECLARATIONS}:
            return
        if not agent_id:
            context.add(Finding("CATALOG_AGENT_ID_MISSING", Severity.ERROR, "record is not attributable to an agent", SourceLocation(document.name, f"/items/{index}")))

    def _check_identifier_namespaces(self, entries: Iterable[CatalogEntry], context: ValidationContext) -> None:
        by_id: dict[str, list[CatalogEntry]] = defaultdict(list)
        for entry in entries:
            by_id[entry.identifier].append(entry)
        permitted_cross_kind = {
            frozenset({DocumentKind.IDENTITIES.value, DocumentKind.DESCRIPTIONS.value}),
        }
        for identifier, group in by_id.items():
            kinds = {entry.kind for entry in group}
            if len(kinds) < 2:
                continue
            if frozenset(kinds) in permitted_cross_kind:
                continue
            context.add(Finding(
                "CATALOG_CROSS_KIND_ID_COLLISION",
                Severity.WARNING,
                "identifier is reused across different material types",
                SourceLocation(group[0].document, group[0].pointer),
                subject=identifier,
                details={"locations": [{"kind": item.kind, "document": item.document, "pointer": item.pointer} for item in group]},
            ))

    def _check_per_agent_inventory(self, entries: Iterable[CatalogEntry], context: ValidationContext) -> None:
        by_agent: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for entry in entries:
            if entry.agent_id:
                by_agent[entry.agent_id][entry.kind] += 1
        required = {
            DocumentKind.IDENTITIES.value,
            DocumentKind.DESCRIPTIONS.value,
            DocumentKind.DISCOVERY.value,
            DocumentKind.INTERACTIONS.value,
            DocumentKind.TOOLS.value,
            DocumentKind.OTA_PLAN.value,
        }
        inventory: dict[str, Any] = {}
        for agent_id, counts in sorted(by_agent.items()):
            missing = sorted(kind for kind in required if counts.get(kind, 0) == 0)
            inventory[agent_id] = {"counts": dict(sorted(counts.items())), "missing": missing}
            if missing:
                context.add(Finding("CATALOG_AGENT_INVENTORY_INCOMPLETE", Severity.ERROR, "agent material inventory is incomplete", SourceLocation("manifest.json", "/documents"), subject=agent_id, details={"missing": missing}))
        context.artifacts["agent_inventory"] = inventory

    def _check_document_cardinality(self, entries: Iterable[CatalogEntry], context: ValidationContext) -> None:
        per_agent_kind: dict[tuple[str, str], list[CatalogEntry]] = defaultdict(list)
        for entry in entries:
            if entry.agent_id:
                per_agent_kind[(entry.agent_id, entry.kind)].append(entry)
        singleton_kinds = {DocumentKind.IDENTITIES.value, DocumentKind.DESCRIPTIONS.value}
        for (agent_id, kind), group in per_agent_kind.items():
            if kind in singleton_kinds and len(group) > 1:
                context.add(Finding("CATALOG_SINGLETON_VIOLATION", Severity.ERROR, "agent has multiple records where exactly one is allowed", SourceLocation(group[1].document, group[1].pointer), subject=agent_id, details={"kind": kind, "record_ids": [item.identifier for item in group]}))
