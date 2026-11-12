from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Mapping

from ..domain import DocumentKind, Finding, PermissionLevel, Severity, SourceLocation, ValidationContext


class RegulatoryPolicyChecker:
    allowed_destination_prefixes = ("local-", "vendor-", "declared-third-party:")
    forbidden_operation_fragments = ("bypass", "disable-audit", "silent-escalation", "unconfirmed-admin")

    def check(self, context: ValidationContext) -> None:
        self._manifest_rules(context)
        self._identity_rules(context)
        self._description_rules(context)
        self._discovery_rules(context)
        self._interaction_rules(context)
        self._tool_rules(context)
        self._declaration_rules(context)
        self._ota_rules(context)
        self._cross_agent_rules(context)

    def _manifest_rules(self, context: ValidationContext) -> None:
        manifest = context.bundle.raw_manifest
        if manifest.get("bundle_id") != context.bundle.bundle_id:
            context.add(self._finding("POLICY_BUNDLE_ID_MISMATCH", Severity.BLOCKER, "bundle identifier changed during compilation", "manifest.json", "/bundle_id"))
        revision = context.bundle.revision
        if not revision or len(revision) > 64:
            context.add(self._finding("POLICY_REVISION_INVALID", Severity.ERROR, "revision must be a concise non-empty identifier", "manifest.json", "/revision"))
        documents = manifest.get("documents", [])
        kinds = [item.get("kind") for item in documents if isinstance(item, Mapping)] if isinstance(documents, list) else []
        duplicate_kinds = sorted(kind for kind, count in Counter(kinds).items() if count > 1)
        if duplicate_kinds:
            context.add(self._finding("POLICY_MANIFEST_DUPLICATE_KIND", Severity.BLOCKER, "manifest lists a document kind more than once", "manifest.json", "/documents", details={"kinds": duplicate_kinds}))
        if manifest.get("runtime_policy") not in (None, "static-review-only"):
            context.add(self._finding("POLICY_RUNTIME_SCOPE_INVALID", Severity.ERROR, "bundle declares a runtime policy although this compiler only reviews static materials", "manifest.json", "/runtime_policy"))

    def _identity_rules(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.IDENTITIES)
        if document is None:
            return
        codes: dict[str, str] = {}
        active_agents = 0
        for index, item in self._items(document.data):
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            code = str(item.get("unique_code", ""))
            if code in codes:
                context.add(Finding("POLICY_IDENTITY_CODE_DUPLICATE", Severity.BLOCKER, "unique identity code is assigned to multiple agents", location, subject=identifier, details={"other_agent": codes[code], "unique_code": code}))
            else:
                codes[code] = identifier
            if item.get("status") == "active":
                active_agents += 1
            if item.get("status") == "retired":
                context.add(Finding("POLICY_RETIRED_AGENT_SUBMITTED", Severity.ERROR, "retired agent must not be included as an active network submission", location, subject=identifier))
            if not str(item.get("vendor", "")).strip() or not str(item.get("product", "")).strip():
                context.add(Finding("POLICY_IDENTITY_OWNER_INCOMPLETE", Severity.ERROR, "identity record lacks vendor or product attribution", location, subject=identifier))
        context.metrics["active_agents"] = active_agents
        context.metrics["identity_codes"] = len(codes)

    def _description_rules(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.DESCRIPTIONS)
        if document is None:
            return
        for index, item in self._items(document.data):
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            purpose = str(item.get("purpose", ""))
            if len(purpose) < 20:
                context.add(Finding("POLICY_PURPOSE_TOO_BRIEF", Severity.WARNING, "agent purpose is too brief for reviewer understanding", location, subject=identifier, details={"length": len(purpose)}))
            destinations = item.get("data_destinations", [])
            if isinstance(destinations, list):
                for destination in destinations:
                    if not isinstance(destination, str) or not destination.startswith(self.allowed_destination_prefixes):
                        context.add(Finding("POLICY_DESTINATION_UNCLASSIFIED", Severity.ERROR, "data destination is not classified for traceability", location, subject=identifier, details={"destination": destination}))
            owner = str(item.get("owner", ""))
            if "@" not in owner and not owner.startswith("team:"):
                context.add(Finding("POLICY_OWNER_UNROUTABLE", Severity.WARNING, "responsible owner is not a routable mailbox or team identifier", location, subject=identifier, details={"owner": owner}))

    def _discovery_rules(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.DISCOVERY)
        if document is None:
            return
        by_agent: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for _, item in self._items(document.data):
            by_agent[str(item.get("agent_id", ""))].append(item)
        for index, item in self._items(document.data):
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            audiences = item.get("audiences", [])
            if item.get("discoverable") is True and isinstance(audiences, list) and "all" in audiences:
                context.add(Finding("POLICY_DISCOVERY_UNBOUNDED", Severity.WARNING, "agent discovery is visible to an unbounded audience", location, subject=identifier))
            channel = str(item.get("channel", ""))
            if channel not in {"device-catalog", "system-search", "application-intent", "vendor-catalog"}:
                context.add(Finding("POLICY_DISCOVERY_CHANNEL_UNKNOWN", Severity.ERROR, "discovery channel is not recognized", location, subject=identifier, details={"channel": channel}))
        for agent_id, records in by_agent.items():
            signatures = {(item.get("channel"), tuple(item.get("audiences", [])), item.get("discoverable")) for item in records}
            if len(signatures) != len(records):
                context.add(Finding("POLICY_DISCOVERY_DUPLICATE", Severity.WARNING, "agent has duplicate discovery declarations", SourceLocation(document.name, "/items"), subject=agent_id))

    def _interaction_rules(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.INTERACTIONS)
        if document is None:
            return
        operations: dict[tuple[str, str], str] = {}
        for index, item in self._items(document.data):
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            operation = str(item.get("operation", "")).lower()
            if any(fragment in operation for fragment in self.forbidden_operation_fragments):
                context.add(Finding("POLICY_OPERATION_FORBIDDEN", Severity.BLOCKER, "capability operation describes a prohibited control bypass", location, subject=identifier, details={"operation": operation}))
            key = (str(item.get("agent_id", "")), operation)
            if key in operations and operations[key] != identifier:
                context.add(Finding("POLICY_OPERATION_DUPLICATE", Severity.ERROR, "same agent operation is declared under multiple capabilities", location, subject=identifier, details={"other_capability": operations[key]}))
            operations[key] = identifier
            try:
                permission = PermissionLevel.parse(item.get("permission", "public"))
            except ValueError:
                continue
            if item.get("category") == "tool_call" and permission.value == PermissionLevel.PUBLIC.value:
                context.add(Finding("POLICY_TOOL_CALL_PUBLIC", Severity.WARNING, "tool-call capability is classified as public permission", location, subject=identifier))

    def _tool_rules(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.TOOLS)
        if document is None:
            return
        for index, item in self._items(document.data):
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            try:
                permission = PermissionLevel.parse(item.get("maximum_permission", "public"))
            except ValueError:
                continue
            if permission.value >= PermissionLevel.USER_DATA.value and item.get("requires_confirmation") is not True:
                context.add(Finding("POLICY_TOOL_CONFIRMATION_REQUIRED", Severity.BLOCKER, "sensitive tool grant must require explicit confirmation", location, subject=identifier))
            if permission.value >= PermissionLevel.USER_DATA.value and item.get("writes_audit_record") is not True:
                context.add(Finding("POLICY_TOOL_AUDIT_REQUIRED", Severity.BLOCKER, "sensitive tool grant must create an approval/audit record", location, subject=identifier))
            declarations = item.get("declaration_ids", [])
            if permission.value >= PermissionLevel.USER_DATA.value and (not isinstance(declarations, list) or not declarations):
                context.add(Finding("POLICY_TOOL_DECLARATION_REQUIRED", Severity.BLOCKER, "sensitive third-party tool grant must reference a signed declaration", location, subject=identifier))

    def _declaration_rules(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.DECLARATIONS)
        if document is None:
            return
        scopes: dict[tuple[str, str], str] = {}
        for index, item in self._items(document.data):
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            if item.get("consent") is not True:
                context.add(Finding("POLICY_DECLARATION_CONSENT_REQUIRED", Severity.BLOCKER, "third-party application must actively declare consent", location, subject=identifier))
            app = str(item.get("application_id", ""))
            for tool_id in item.get("tool_ids", []) if isinstance(item.get("tool_ids"), list) else []:
                key = (app, str(tool_id))
                if key in scopes:
                    context.add(Finding("POLICY_DECLARATION_SCOPE_DUPLICATE", Severity.WARNING, "application repeats consent for the same tool", location, subject=identifier, details={"other_declaration": scopes[key], "tool_id": tool_id}))
                scopes[key] = identifier

    def _ota_rules(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.OTA_PLAN)
        if document is None:
            return
        for index, item in self._items(document.data):
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            if item.get("from_version") == item.get("to_version"):
                context.add(Finding("POLICY_OTA_VERSION_UNCHANGED", Severity.ERROR, "OTA plan has identical source and target versions", location, subject=identifier))
            assessment = item.get("impact_assessment", {})
            if isinstance(assessment, Mapping) and assessment.get("rollback") in (None, "", False, "not-applicable"):
                context.add(Finding("POLICY_OTA_ROLLBACK_UNDEFINED", Severity.ERROR, "OTA plan does not define a rollback assessment", location, subject=identifier))

    def _cross_agent_rules(self, context: ValidationContext) -> None:
        identities = self._ids(context, DocumentKind.IDENTITIES)
        descriptions = self._agent_ids(context, DocumentKind.DESCRIPTIONS)
        discovery = self._agent_ids(context, DocumentKind.DISCOVERY)
        interactions = self._agent_ids(context, DocumentKind.INTERACTIONS)
        tools = self._agent_ids(context, DocumentKind.TOOLS)
        ota = self._agent_ids(context, DocumentKind.OTA_PLAN)
        required_sets = {"descriptions": descriptions, "discovery": discovery, "interactions": interactions, "tools": tools, "ota_plan": ota}
        for name, values in required_sets.items():
            missing = sorted(identities - values)
            unexpected = sorted(values - identities)
            if missing:
                context.add(Finding("POLICY_AGENT_MATERIAL_MISSING", Severity.ERROR, "one or more agents lack required material", SourceLocation("manifest.json", "/documents"), details={"document_kind": name, "agent_ids": missing}))
            if unexpected:
                context.add(Finding("POLICY_AGENT_UNKNOWN", Severity.BLOCKER, "material refers to an agent absent from the identity list", SourceLocation("manifest.json", "/documents"), details={"document_kind": name, "agent_ids": unexpected}))

    def _ids(self, context: ValidationContext, kind: DocumentKind) -> set[str]:
        document = context.bundle.get(kind)
        return {str(item.get("id")) for _, item in self._items(document.data if document else {}) if item.get("id")}

    def _agent_ids(self, context: ValidationContext, kind: DocumentKind) -> set[str]:
        document = context.bundle.get(kind)
        return {str(item.get("agent_id")) for _, item in self._items(document.data if document else {}) if item.get("agent_id")}

    def _items(self, data: Mapping[str, Any]) -> list[tuple[int, Mapping[str, Any]]]:
        items = data.get("items", [])
        if not isinstance(items, list):
            return []
        return [(index, item) for index, item in enumerate(items) if isinstance(item, Mapping)]

    def _finding(self, code: str, severity: Severity, message: str, document: str, pointer: str, *, subject: str = "", details: dict[str, Any] | None = None) -> Finding:
        return Finding(code, severity, message, SourceLocation(document, pointer), subject=subject, details=details or {})
