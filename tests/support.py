from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
import subprocess
import sys
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping

from agentgate.domain import DocumentKind, Finding, Severity, SourceLocation, ValidationContext
from agentgate.pipeline import CompilationPipeline
from agentgate.review.signatures import DeclarationSignatureVerifier


TRUST_KEY = "local-demo-signing-key"
SIGNER = "vendor-release-key"
NOW = "2026-11-01T08:00:00+00:00"


def digest(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def declaration_signature(item: Mapping[str, Any], key: str = TRUST_KEY) -> tuple[str, str]:
    payload = DeclarationSignatureVerifier.canonical_payload(item)
    return hashlib.sha256(payload).hexdigest(), hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def base_documents() -> dict[str, dict[str, Any]]:
    documents: dict[str, dict[str, Any]] = {
        "identities.json": {
            "schema_version": "2.0",
            "items": [
                {
                    "id": "agent-alpha",
                    "unique_code": "AGT-ALPHA0001",
                    "vendor": "Northwind Devices",
                    "product": "Northwind Assistant Phone",
                    "status": "active",
                    "evidence_ids": ["ev-identity"],
                }
            ],
        },
        "descriptions.json": {
            "schema_version": "2.0",
            "items": [
                {
                    "id": "desc-alpha",
                    "agent_id": "agent-alpha",
                    "display_name": "Northwind Travel Assistant",
                    "purpose": "Coordinates user-confirmed travel reservations and records each external application handoff.",
                    "owner": "team:assistant-compliance",
                    "data_destinations": ["local-device", "declared-third-party:app-weather"],
                }
            ],
        },
        "discovery.json": {
            "schema_version": "2.0",
            "items": [
                {
                    "id": "discover-alpha",
                    "agent_id": "agent-alpha",
                    "channel": "device-catalog",
                    "discoverable": True,
                    "audiences": ["device-owner"],
                }
            ],
        },
        "interactions.json": {
            "schema_version": "2.0",
            "items": [
                {
                    "id": "cap-reserve",
                    "agent_id": "agent-alpha",
                    "operation": "reserve-itinerary",
                    "category": "tool_call",
                    "permission": "user_data",
                    "approval_required": True,
                    "audit_required": True,
                    "tool_ids": ["tool-reserve"],
                    "evidence_ids": ["ev-cap-auth", "ev-cap-audit"],
                }
            ],
        },
        "tools.json": {
            "schema_version": "2.0",
            "items": [
                {
                    "id": "tool-reserve",
                    "agent_id": "agent-alpha",
                    "operation": "reserve-itinerary",
                    "maximum_permission": "user_data",
                    "requires_confirmation": True,
                    "writes_audit_record": True,
                    "declaration_ids": ["dec-weather"],
                }
            ],
        },
        "ota-plan.json": {
            "schema_version": "2.0",
            "items": [
                {
                    "id": "ota-202611",
                    "agent_id": "agent-alpha",
                    "from_version": "1.0.0",
                    "to_version": "1.1.0",
                    "scheme_submitted": True,
                    "completion_report_required": True,
                    "impact_assessment": {
                        "identity": "reviewed",
                        "capabilities": "reviewed",
                        "permissions": "reviewed",
                        "evidence": "reviewed",
                        "rollback": "defined",
                    },
                    "evidence_ids": ["ev-ota"],
                }
            ],
        },
        "declarations.json": {
            "schema_version": "2.0",
            "items": [
                {
                    "id": "dec-weather",
                    "application_id": "app-weather",
                    "agent_id": "agent-alpha",
                    "tool_ids": ["tool-reserve"],
                    "consent": True,
                    "signature_algorithm": "hmac-sha256",
                    "signer": SIGNER,
                    "payload_digest": "",
                    "signature": "",
                    "evidence_ids": ["ev-declaration"],
                }
            ],
        },
        "evidence.json": {
            "schema_version": "2.0",
            "items": [
                evidence("ev-cap-auth", "control-test", "interactions", "cap-reserve", "authorization_controls"),
                evidence("ev-cap-audit", "log-proof", "interactions", "cap-reserve", "audit_record_created"),
                evidence("ev-identity", "registry-check", "identities", "agent-alpha", "unique_code_registered"),
                evidence("ev-declaration", "signature-check", "declarations", "dec-weather", "signature_verified"),
                evidence("ev-ota", "review-record", "ota_plan", "ota-202611", "impact_assessment_reviewed"),
            ],
        },
    }
    sign_declarations(documents)
    documents["baseline.json"] = baseline_document(documents)
    return documents


def evidence(identifier: str, evidence_type: str, subject_kind: str, subject_id: str, assertion: str, *, result: str = "pass", executed_at: str = NOW) -> dict[str, Any]:
    return {
        "id": identifier,
        "type": evidence_type,
        "subject_kind": subject_kind,
        "subject_id": subject_id,
        "assertion": assertion,
        "result": result,
        "artifact_digest": digest(identifier + assertion),
        "executed_at": executed_at,
    }


def sign_declarations(documents: dict[str, dict[str, Any]], key: str = TRUST_KEY) -> None:
    document = documents.get("declarations.json", {})
    items = document.get("items", [])
    if not isinstance(items, list):
        return
    for item in items:
        if not isinstance(item, dict):
            continue
        item["payload_digest"] = ""
        item["signature"] = ""
        payload_digest, signature = declaration_signature(item, key)
        item["payload_digest"] = payload_digest
        item["signature"] = signature


def baseline_document(documents: Mapping[str, Mapping[str, Any]]) -> dict[str, Any]:
    kind_by_name = {
        "identities.json": "identities",
        "descriptions.json": "descriptions",
        "discovery.json": "discovery",
        "interactions.json": "interactions",
        "tools.json": "tools",
        "ota-plan.json": "ota_plan",
        "declarations.json": "declarations",
    }
    items: list[dict[str, Any]] = []
    for name, kind in kind_by_name.items():
        document = documents.get(name, {})
        values = document.get("items", []) if isinstance(document, Mapping) else []
        if not isinstance(values, list):
            continue
        for item in values:
            if not isinstance(item, Mapping) or not isinstance(item.get("id"), str):
                continue
            snapshot = copy.deepcopy(dict(item))
            payload = json.dumps(snapshot, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            items.append({
                "id": f"{kind}:{item['id']}",
                "kind": kind,
                "subject_id": item["id"],
                "fingerprint": hashlib.sha256(payload.encode("utf-8")).hexdigest(),
                "snapshot": snapshot,
            })
    return {"schema_version": "2.0", "items": items}


def manifest_for(documents: Mapping[str, Mapping[str, Any]], *, bundle_id: str = "AGB-NORTHWIND-202611", revision: str = "r1", include_digests: bool = True) -> dict[str, Any]:
    kind_by_name = {
        "identities.json": "identities",
        "descriptions.json": "descriptions",
        "discovery.json": "discovery",
        "interactions.json": "interactions",
        "tools.json": "tools",
        "ota-plan.json": "ota_plan",
        "declarations.json": "declarations",
        "evidence.json": "evidence",
        "baseline.json": "baseline",
        "closures.json": "closures",
    }
    entries: list[dict[str, Any]] = []
    for name in sorted(documents):
        if name not in kind_by_name:
            continue
        encoded = encode_json(documents[name])
        version = str(documents[name].get("schema_version", "2.0"))
        entry = {"kind": kind_by_name[name], "path": name, "version": version}
        if include_digests:
            entry["sha256"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        entries.append(entry)
    return {
        "bundle_id": bundle_id,
        "revision": revision,
        "schema_version": "2.0",
        "submitted_at": NOW,
        "runtime_policy": "static-review-only",
        "local_trust_keys": {SIGNER: TRUST_KEY},
        "documents": entries,
    }


def encode_json(value: Mapping[str, Any]) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"


def write_bundle(root: Path, documents: Mapping[str, Mapping[str, Any]], *, manifest: Mapping[str, Any] | None = None) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for name, value in documents.items():
        (root / name).write_text(encode_json(value), encoding="utf-8")
    effective_manifest = dict(manifest or manifest_for(documents))
    (root / "manifest.json").write_text(encode_json(effective_manifest), encoding="utf-8")
    return root


@contextmanager
def temporary_bundle(mutator: Callable[[dict[str, dict[str, Any]]], None] | None = None, *, refresh_baseline: bool = True, revision: str = "r1", include_digests: bool = True, resign: bool = True) -> Iterator[Path]:
    with tempfile.TemporaryDirectory() as directory:
        documents = base_documents()
        if mutator is not None:
            mutator(documents)
        if resign:
            sign_declarations(documents)
        if refresh_baseline:
            documents["baseline.json"] = baseline_document(documents)
        manifest = manifest_for(documents, revision=revision, include_digests=include_digests)
        yield write_bundle(Path(directory) / "bundle", documents, manifest=manifest)


def finding_codes(result: Any) -> set[str]:
    return {finding.code for finding in result.findings}


def findings_by_code(result: Any, code: str) -> list[Finding]:
    return [finding for finding in result.findings if finding.code == code]


def make_context(findings: list[Finding]) -> ValidationContext:
    with temporary_bundle() as root:
        bundle = __import__("agentgate.bundle", fromlist=["BundleReader"]).BundleReader(root).read()
    context = ValidationContext(bundle)
    context.findings.extend(findings)
    return context


def sample_finding(code: str, severity: Severity = Severity.ERROR, *, document: str = "interactions.json", pointer: str = "/items/0", subject: str = "cap-reserve", details: dict[str, Any] | None = None) -> Finding:
    finding = Finding(code, severity, f"message for {code}", SourceLocation(document, pointer), subject=subject, details=details or {})
    finding.fingerprint = digest(code + document + pointer + subject)
    return finding


def run_cli(arguments: list[str], *, cwd: str | Path | None = None) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    project = str(Path(__file__).resolve().parents[1])
    environment["PYTHONPATH"] = project + (os.pathsep + environment["PYTHONPATH"] if environment.get("PYTHONPATH") else "")
    return subprocess.run(
        [sys.executable, "-m", "agentgate", *arguments],
        cwd=cwd,
        env=environment,
        text=True,
        encoding="utf-8",
        capture_output=True,
        timeout=20,
        check=False,
    )
