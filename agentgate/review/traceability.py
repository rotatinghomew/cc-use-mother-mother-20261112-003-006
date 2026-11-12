from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..domain import DocumentKind, Finding, Severity, SourceLocation, ValidationContext


@dataclass(frozen=True)
class TraceLink:
    agent_id: str
    source_kind: str
    source_id: str
    target_kind: str
    target_id: str
    reason: str

    def as_dict(self) -> dict[str, str]:
        return {
            "agent_id": self.agent_id,
            "source_kind": self.source_kind,
            "source_id": self.source_id,
            "target_kind": self.target_kind,
            "target_id": self.target_id,
            "reason": self.reason,
        }


class TraceabilityLedger:
    def build(self, context: ValidationContext) -> list[TraceLink]:
        links: list[TraceLink] = []
        capabilities = self._items(context, DocumentKind.INTERACTIONS)
        tools = {str(item.get("id")): item for item in self._items(context, DocumentKind.TOOLS)}
        declarations = {str(item.get("id")): item for item in self._items(context, DocumentKind.DECLARATIONS)}
        evidence = {str(item.get("id")): item for item in self._items(context, DocumentKind.EVIDENCE)}
        ota_plans = self._items(context, DocumentKind.OTA_PLAN)
        descriptions = self._items(context, DocumentKind.DESCRIPTIONS)
        discoveries = self._items(context, DocumentKind.DISCOVERY)
        for capability in capabilities:
            capability_id = str(capability.get("id", ""))
            agent_id = str(capability.get("agent_id", ""))
            for tool_id in capability.get("tool_ids", []) if isinstance(capability.get("tool_ids"), list) else []:
                links.append(TraceLink(agent_id, "capability", capability_id, "tool", str(tool_id), "declared tool implementation"))
                tool = tools.get(str(tool_id))
                if tool is not None:
                    for declaration_id in tool.get("declaration_ids", []) if isinstance(tool.get("declaration_ids"), list) else []:
                        links.append(TraceLink(agent_id, "tool", str(tool_id), "declaration", str(declaration_id), "third-party consent scope"))
            for evidence_id in capability.get("evidence_ids", []) if isinstance(capability.get("evidence_ids"), list) else []:
                links.append(TraceLink(agent_id, "capability", capability_id, "evidence", str(evidence_id), "control verification"))
        for ota in ota_plans:
            ota_id = str(ota.get("id", ""))
            agent_id = str(ota.get("agent_id", ""))
            for evidence_id in ota.get("evidence_ids", []) if isinstance(ota.get("evidence_ids"), list) else []:
                links.append(TraceLink(agent_id, "ota_plan", ota_id, "evidence", str(evidence_id), "upgrade impact validation"))
        for description in descriptions:
            agent_id = str(description.get("agent_id", ""))
            links.append(TraceLink(agent_id, "identity", agent_id, "description", str(description.get("id", "")), "public agent description"))
        for discovery in discoveries:
            agent_id = str(discovery.get("agent_id", ""))
            links.append(TraceLink(agent_id, "identity", agent_id, "discovery", str(discovery.get("id", "")), "discovery exposure declaration"))
        self._validate_links(links, tools, declarations, evidence, context)
        self._validate_paths(links, context)
        self._validate_destination_trace(context)
        context.artifacts["traceability_ledger"] = [link.as_dict() for link in links]
        context.metrics["trace_links"] = len(links)
        return links

    def _validate_links(
        self,
        links: Iterable[TraceLink],
        tools: Mapping[str, Mapping[str, Any]],
        declarations: Mapping[str, Mapping[str, Any]],
        evidence: Mapping[str, Mapping[str, Any]],
        context: ValidationContext,
    ) -> None:
        registries = {"tool": tools, "declaration": declarations, "evidence": evidence}
        for link in links:
            registry = registries.get(link.target_kind)
            if registry is not None and link.target_id not in registry:
                context.add(Finding("TRACE_TARGET_MISSING", Severity.ERROR, "traceability link points to a missing target", SourceLocation("manifest.json", "/documents"), subject=link.source_id, details=link.as_dict()))
                continue
            target = registry.get(link.target_id) if registry is not None else None
            if target is not None:
                target_agent = str(target.get("agent_id", ""))
                if target_agent and target_agent != link.agent_id:
                    context.add(Finding("TRACE_AGENT_MISMATCH", Severity.ERROR, "traceability link crosses agent ownership", SourceLocation("manifest.json", "/documents"), subject=link.source_id, details={**link.as_dict(), "target_agent": target_agent}))

    def _validate_paths(self, links: Iterable[TraceLink], context: ValidationContext) -> None:
        outgoing: dict[tuple[str, str], list[TraceLink]] = defaultdict(list)
        for link in links:
            outgoing[(link.source_kind, link.source_id)].append(link)
        capabilities = self._items(context, DocumentKind.INTERACTIONS)
        tools = {str(item.get("id")): item for item in self._items(context, DocumentKind.TOOLS)}
        for capability in capabilities:
            capability_id = str(capability.get("id", ""))
            tool_links = [link for link in outgoing.get(("capability", capability_id), []) if link.target_kind == "tool"]
            evidence_links = [link for link in outgoing.get(("capability", capability_id), []) if link.target_kind == "evidence"]
            if capability.get("category") == "tool_call" and not tool_links:
                context.add(Finding("TRACE_CAPABILITY_TOOL_PATH_MISSING", Severity.ERROR, "tool-call capability lacks a trace path to a tool", SourceLocation("interactions.json", "/items"), subject=capability_id))
            if not evidence_links:
                context.add(Finding("TRACE_CAPABILITY_EVIDENCE_PATH_MISSING", Severity.ERROR, "capability lacks a trace path to test evidence", SourceLocation("interactions.json", "/items"), subject=capability_id))
            for tool_link in tool_links:
                declaration_links = [link for link in outgoing.get(("tool", tool_link.target_id), []) if link.target_kind == "declaration"]
                tool = tools.get(tool_link.target_id, {})
                if tool.get("declaration_ids") and not declaration_links:
                    context.add(Finding("TRACE_TOOL_DECLARATION_PATH_MISSING", Severity.ERROR, "tool lacks a trace path to its declared consent", SourceLocation("tools.json", "/items"), subject=tool_link.target_id))

    def _validate_destination_trace(self, context: ValidationContext) -> None:
        descriptions = self._items(context, DocumentKind.DESCRIPTIONS)
        declarations = self._items(context, DocumentKind.DECLARATIONS)
        declared_apps = {str(item.get("application_id", "")) for item in declarations}
        for description in descriptions:
            identifier = str(description.get("id", ""))
            destinations = description.get("data_destinations", [])
            if not isinstance(destinations, list):
                continue
            for destination in destinations:
                if not isinstance(destination, str) or not destination.startswith("declared-third-party:"):
                    continue
                application_id = destination.split(":", 1)[1]
                if application_id not in declared_apps:
                    context.add(Finding("TRACE_DESTINATION_DECLARATION_MISSING", Severity.BLOCKER, "third-party data destination has no signed application declaration", SourceLocation("descriptions.json", "/items"), subject=identifier, details={"application_id": application_id}))

    def _items(self, context: ValidationContext, kind: DocumentKind) -> list[Mapping[str, Any]]:
        document = context.bundle.get(kind)
        if document is None:
            return []
        items = document.data.get("items", [])
        return [item for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []
