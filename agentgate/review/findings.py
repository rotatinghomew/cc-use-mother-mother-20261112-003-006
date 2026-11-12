from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..domain import Finding, FindingState, Severity, ValidationContext, utc_now


class FindingManager:
    severity_order = {Severity.BLOCKER: 0, Severity.ERROR: 1, Severity.WARNING: 2, Severity.INFO: 3}

    def finalize(self, context: ValidationContext) -> list[Finding]:
        revision = context.bundle.revision
        unique: dict[str, Finding] = {}
        for finding in context.findings:
            finding.fingerprint = self.fingerprint(finding)
            finding.first_seen_revision = finding.first_seen_revision or revision
            finding.last_seen_revision = revision
            current = unique.get(finding.fingerprint)
            if current is None or self.severity_order[finding.severity] < self.severity_order[current.severity]:
                unique[finding.fingerprint] = finding
        context.findings[:] = sorted(
            unique.values(),
            key=lambda item: (self.severity_order[item.severity], item.code, item.location.document, item.location.pointer, item.subject),
        )
        context.metrics["findings_total"] = len(context.findings)
        for severity in Severity:
            context.metrics[f"findings_{severity.value}"] = sum(item.severity is severity for item in context.findings)
        return context.findings

    def fingerprint(self, finding: Finding) -> str:
        identity = {
            "code": finding.code,
            "document": finding.location.document,
            "pointer": finding.location.pointer,
            "subject": finding.subject,
        }
        payload = json.dumps(identity, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ReturnListBuilder:
    def build(self, context: ValidationContext) -> dict[str, Any]:
        actionable = [item for item in context.findings if item.state not in {FindingState.VERIFIED, FindingState.WAIVED} and item.severity in {Severity.BLOCKER, Severity.ERROR, Severity.WARNING}]
        grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in actionable:
            grouped[item.location.document].append({
                "fingerprint": item.fingerprint,
                "code": item.code,
                "severity": item.severity.value,
                "pointer": item.location.pointer,
                "subject": item.subject,
                "message": item.message,
                "details": item.details,
                "required_action": self._required_action(item),
            })
        return {
            "format": "agent-gate-return-list/v1",
            "bundle_id": context.bundle.bundle_id,
            "revision": context.bundle.revision,
            "generated_at": utc_now(),
            "decision": context.decision().value,
            "summary": dict(Counter(item.severity.value for item in actionable)),
            "documents": [{"document": key, "items": grouped[key]} for key in sorted(grouped)],
        }

    def _required_action(self, finding: Finding) -> str:
        prefixes = {
            "SCHEMA": "修正申报文档格式并重新生成材料",
            "REFERENCE": "补齐或校正跨文档引用关系",
            "MATRIX": "统一能力、权限、确认、审计和声明配置",
            "EVIDENCE": "补交与目标控制直接绑定的有效测试证据",
            "OTA": "补齐升级方案、影响评估或完成报告要求",
            "DIFF": "解释并覆盖相对基线的实质变化",
            "SIGNATURE": "重新生成可信签名声明",
            "CLOSURE": "修正缺陷闭环动作或补充验证证据",
        }
        return prefixes.get(finding.code.split("_", 1)[0], "核对申报材料并修正该缺陷")


class ReviewPackageBuilder:
    def build(self, context: ValidationContext) -> dict[str, Any]:
        documents = [
            {
                "kind": document.kind.value,
                "name": document.name,
                "version": document.version,
                "sha256": document.digest,
                "items": len(document.data.get("items", [])) if isinstance(document.data.get("items"), list) else None,
            }
            for document in context.bundle.all_documents()
        ]
        open_findings = [item for item in context.findings if item.state not in {FindingState.VERIFIED, FindingState.WAIVED}]
        return {
            "format": "agent-gate-review-package/v1",
            "bundle": {
                "bundle_id": context.bundle.bundle_id,
                "revision": context.bundle.revision,
                "schema_version": context.bundle.schema_version,
                "submitted_at": context.bundle.submitted_at,
            },
            "generated_at": utc_now(),
            "decision": context.decision().value,
            "documents": documents,
            "metrics": dict(sorted(context.metrics.items())),
            "finding_summary": dict(Counter(item.severity.value for item in open_findings)),
            "findings": [item.as_dict() for item in context.findings],
            "reference_graph": context.artifacts.get("reference_graph", {}),
            "capability_matrix": context.artifacts.get("capability_matrix", []),
            "evidence_coverage": context.artifacts.get("evidence_coverage", []),
            "baseline_diff": context.artifacts.get("baseline_diff", []),
            "submission_catalog": context.artifacts.get("submission_catalog", []),
            "agent_inventory": context.artifacts.get("agent_inventory", {}),
            "traceability_ledger": context.artifacts.get("traceability_ledger", []),
            "normalization": context.artifacts.get("normalization", []),
            "remediation_plan": context.artifacts.get("remediation_plan", {}),
            "integrity": self._integrity(context),
        }

    def _integrity(self, context: ValidationContext) -> dict[str, str]:
        payload = {
            "bundle_id": context.bundle.bundle_id,
            "revision": context.bundle.revision,
            "documents": {document.name: document.digest for document in context.bundle.all_documents()},
            "findings": [item.fingerprint for item in context.findings],
        }
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {"algorithm": "sha256", "digest": hashlib.sha256(encoded).hexdigest()}
