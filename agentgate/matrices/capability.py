from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..domain import Capability, DocumentKind, Finding, PermissionLevel, Severity, SourceLocation, ToolGrant, ValidationContext


@dataclass(frozen=True)
class MatrixCell:
    agent_id: str
    capability_id: str
    tool_id: str
    requested: PermissionLevel
    granted: PermissionLevel
    approval_required: bool
    confirmation_present: bool
    audit_required: bool
    audit_present: bool
    declarations: tuple[str, ...]

    @property
    def permission_ok(self) -> bool:
        return self.granted.value >= self.requested.value

    @property
    def approval_ok(self) -> bool:
        return not self.approval_required or self.confirmation_present

    @property
    def audit_ok(self) -> bool:
        return not self.audit_required or self.audit_present

    @property
    def declaration_ok(self) -> bool:
        return bool(self.declarations)

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "capability_id": self.capability_id,
            "tool_id": self.tool_id,
            "requested": self.requested.name.lower(),
            "granted": self.granted.name.lower(),
            "permission_ok": self.permission_ok,
            "approval_required": self.approval_required,
            "confirmation_present": self.confirmation_present,
            "audit_required": self.audit_required,
            "audit_present": self.audit_present,
            "declarations": list(self.declarations),
            "declaration_ok": self.declaration_ok,
        }


class CapabilityMatrixChecker:
    sensitive_threshold = PermissionLevel.USER_DATA
    privileged_threshold = PermissionLevel.SYSTEM

    def check(self, context: ValidationContext) -> list[MatrixCell]:
        capabilities = self._capabilities(context)
        tools = self._tools(context)
        declarations = self._declarations(context)
        tools_by_id = {item.tool_id: item for item in tools}
        declarations_by_id = {str(item.get("id")): item for item in declarations}
        cells: list[MatrixCell] = []
        for capability in capabilities:
            self._check_capability_shape(capability, context)
            if not capability.declared_tools and capability.category == "tool_call":
                context.add(self._finding("MATRIX_TOOL_REQUIRED", Severity.ERROR, "tool-call capability declares no tool", capability.source, capability.capability_id))
            for tool_id in capability.declared_tools:
                tool = tools_by_id.get(tool_id)
                if tool is None:
                    continue
                cell = MatrixCell(
                    agent_id=capability.agent_id,
                    capability_id=capability.capability_id,
                    tool_id=tool_id,
                    requested=capability.permission,
                    granted=tool.maximum_permission,
                    approval_required=capability.approval_required or capability.permission.value >= self.sensitive_threshold.value,
                    confirmation_present=tool.requires_confirmation,
                    audit_required=capability.audit_required or capability.permission.value >= self.sensitive_threshold.value,
                    audit_present=tool.writes_audit_record,
                    declarations=tool.declaration_ids,
                )
                cells.append(cell)
                self._check_cell(cell, capability, tool, declarations_by_id, context)
        self._check_unused_tools(tools, cells, context)
        self._check_agent_operation_conflicts(capabilities, context)
        self._check_declaration_scope(tools, declarations_by_id, context)
        self._check_privileged_controls(cells, context)
        context.artifacts["capability_matrix"] = [cell.as_dict() for cell in cells]
        context.metrics["capability_count"] = len(capabilities)
        context.metrics["tool_count"] = len(tools)
        context.metrics["matrix_cells"] = len(cells)
        context.metrics["sensitive_cells"] = sum(cell.requested.value >= self.sensitive_threshold.value for cell in cells)
        return cells

    def _capabilities(self, context: ValidationContext) -> list[Capability]:
        document = context.bundle.get(DocumentKind.INTERACTIONS)
        if document is None:
            return []
        output: list[Capability] = []
        items = document.data.get("items", [])
        if not isinstance(items, list):
            return output
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                continue
            try:
                output.append(Capability.from_mapping(item, SourceLocation(document.name, f"/items/{index}")))
            except ValueError as exc:
                context.add(self._finding("MATRIX_PERMISSION_INVALID", Severity.ERROR, str(exc), SourceLocation(document.name, f"/items/{index}/permission"), str(item.get("id", ""))))
        return output

    def _tools(self, context: ValidationContext) -> list[ToolGrant]:
        document = context.bundle.get(DocumentKind.TOOLS)
        if document is None:
            return []
        output: list[ToolGrant] = []
        items = document.data.get("items", [])
        if not isinstance(items, list):
            return output
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                continue
            try:
                output.append(ToolGrant.from_mapping(item, SourceLocation(document.name, f"/items/{index}")))
            except ValueError as exc:
                context.add(self._finding("MATRIX_TOOL_PERMISSION_INVALID", Severity.ERROR, str(exc), SourceLocation(document.name, f"/items/{index}/maximum_permission"), str(item.get("id", ""))))
        return output

    def _declarations(self, context: ValidationContext) -> list[Mapping[str, Any]]:
        document = context.bundle.get(DocumentKind.DECLARATIONS)
        if document is None:
            return []
        items = document.data.get("items", [])
        return [item for item in items if isinstance(item, Mapping)] if isinstance(items, list) else []

    def _check_capability_shape(self, capability: Capability, context: ValidationContext) -> None:
        if capability.category == "discovery" and capability.permission.value > PermissionLevel.DEVICE.value:
            context.add(self._finding("MATRIX_DISCOVERY_OVERPRIVILEGED", Severity.ERROR, "discovery capability requests excessive permission", capability.source, capability.capability_id, {"permission": capability.permission.name.lower()}))
        if capability.permission.value >= self.sensitive_threshold.value and not capability.approval_required:
            context.add(self._finding("MATRIX_APPROVAL_NOT_DECLARED", Severity.ERROR, "sensitive capability does not declare approval", capability.source, capability.capability_id))
        if capability.permission.value >= self.sensitive_threshold.value and not capability.audit_required:
            context.add(self._finding("MATRIX_AUDIT_NOT_DECLARED", Severity.ERROR, "sensitive capability does not declare audit recording", capability.source, capability.capability_id))
        if capability.permission.value >= self.privileged_threshold.value and not capability.declared_evidence:
            context.add(self._finding("MATRIX_PRIVILEGED_EVIDENCE_MISSING", Severity.BLOCKER, "privileged capability has no declared evidence", capability.source, capability.capability_id))

    def _check_cell(
        self,
        cell: MatrixCell,
        capability: Capability,
        tool: ToolGrant,
        declarations: Mapping[str, Mapping[str, Any]],
        context: ValidationContext,
    ) -> None:
        if tool.agent_id != capability.agent_id:
            context.add(self._finding("MATRIX_AGENT_MISMATCH", Severity.ERROR, "capability and tool belong to different agents", tool.source, tool.tool_id, {"capability_agent": capability.agent_id, "tool_agent": tool.agent_id}))
        if tool.operation != capability.operation:
            context.add(self._finding("MATRIX_OPERATION_MISMATCH", Severity.ERROR, "capability operation differs from tool operation", tool.source, tool.tool_id, {"capability_operation": capability.operation, "tool_operation": tool.operation}))
        if not cell.permission_ok:
            context.add(self._finding("MATRIX_GRANT_TOO_LOW", Severity.ERROR, "tool grant is lower than capability permission", tool.source, tool.tool_id, {"requested": cell.requested.name.lower(), "granted": cell.granted.name.lower()}))
        if not cell.approval_ok:
            context.add(self._finding("MATRIX_CONFIRMATION_MISSING", Severity.BLOCKER, "sensitive tool can be called without user confirmation", tool.source, tool.tool_id))
        if not cell.audit_ok:
            context.add(self._finding("MATRIX_AUDIT_RECORD_MISSING", Severity.BLOCKER, "sensitive tool call does not create an audit record", tool.source, tool.tool_id))
        if cell.requested.value >= self.sensitive_threshold.value and not cell.declaration_ok:
            context.add(self._finding("MATRIX_DECLARATION_MISSING", Severity.BLOCKER, "sensitive third-party call has no signed declaration", tool.source, tool.tool_id))
        for declaration_id in cell.declarations:
            declaration = declarations.get(declaration_id)
            if declaration is None:
                continue
            if declaration.get("agent_id") != capability.agent_id:
                context.add(self._finding("MATRIX_DECLARATION_AGENT_MISMATCH", Severity.ERROR, "declaration names a different agent", tool.source, tool.tool_id, {"declaration_id": declaration_id}))
            declared_tools = declaration.get("tool_ids", [])
            if not isinstance(declared_tools, list) or tool.tool_id not in declared_tools:
                context.add(self._finding("MATRIX_DECLARATION_SCOPE_MISMATCH", Severity.ERROR, "declaration does not cover the tool", tool.source, tool.tool_id, {"declaration_id": declaration_id}))
            if declaration.get("consent") is not True:
                context.add(self._finding("MATRIX_DECLARATION_NO_CONSENT", Severity.BLOCKER, "third party did not actively consent to the call", tool.source, tool.tool_id, {"declaration_id": declaration_id}))

    def _check_unused_tools(self, tools: Iterable[ToolGrant], cells: Iterable[MatrixCell], context: ValidationContext) -> None:
        used = {cell.tool_id for cell in cells}
        for tool in tools:
            if tool.tool_id not in used:
                context.add(self._finding("MATRIX_UNUSED_TOOL", Severity.WARNING, "tool grant is not referenced by any capability", tool.source, tool.tool_id))

    def _check_agent_operation_conflicts(self, capabilities: Iterable[Capability], context: ValidationContext) -> None:
        grouped: dict[tuple[str, str], list[Capability]] = defaultdict(list)
        for capability in capabilities:
            grouped[(capability.agent_id, capability.operation)].append(capability)
        for key, group in grouped.items():
            permissions = {item.permission for item in group}
            approvals = {item.approval_required for item in group}
            audits = {item.audit_required for item in group}
            if len(permissions) > 1 or len(approvals) > 1 or len(audits) > 1:
                context.add(self._finding("MATRIX_OPERATION_CONFLICT", Severity.ERROR, "same agent operation has conflicting control declarations", group[0].source, f"{key[0]}:{key[1]}", {"capability_ids": [item.capability_id for item in group]}))

    def _check_declaration_scope(self, tools: Iterable[ToolGrant], declarations: Mapping[str, Mapping[str, Any]], context: ValidationContext) -> None:
        known_tools = {tool.tool_id for tool in tools}
        for identifier, declaration in declarations.items():
            tool_ids = declaration.get("tool_ids", [])
            if not isinstance(tool_ids, list):
                continue
            unknown = sorted({str(item) for item in tool_ids} - known_tools)
            if unknown:
                context.add(self._finding("MATRIX_DECLARATION_UNKNOWN_TOOL", Severity.ERROR, "declaration contains unknown tools", SourceLocation("declarations.json", "/items"), identifier, {"unknown_tools": unknown}))

    def _check_privileged_controls(self, cells: Iterable[MatrixCell], context: ValidationContext) -> None:
        by_agent: dict[str, list[MatrixCell]] = defaultdict(list)
        for cell in cells:
            by_agent[cell.agent_id].append(cell)
        for agent_id, group in by_agent.items():
            privileged = [cell for cell in group if cell.requested.value >= self.privileged_threshold.value]
            if len(privileged) > 3:
                context.add(self._finding("MATRIX_PRIVILEGED_CONCENTRATION", Severity.WARNING, "agent exposes an unusually broad privileged tool surface", SourceLocation("tools.json", "/items"), agent_id, {"tool_ids": sorted(cell.tool_id for cell in privileged)}))

    def _finding(self, code: str, severity: Severity, message: str, source: SourceLocation, subject: str, details: dict[str, Any] | None = None) -> Finding:
        return Finding(code, severity, message, source, subject=subject, details=details or {})
