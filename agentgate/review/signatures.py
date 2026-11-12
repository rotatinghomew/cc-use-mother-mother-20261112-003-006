from __future__ import annotations

import hashlib
import hmac
import json
from typing import Any, Mapping

from ..domain import DocumentKind, Finding, Severity, SourceLocation, ValidationContext


class DeclarationSignatureVerifier:
    def __init__(self, trust_keys: Mapping[str, str] | None = None) -> None:
        self.trust_keys = dict(trust_keys or {})

    def verify(self, context: ValidationContext) -> None:
        document = context.bundle.get(DocumentKind.DECLARATIONS)
        if document is None:
            return
        declared_keys = context.bundle.raw_manifest.get("local_trust_keys", {})
        keys = dict(self.trust_keys)
        if isinstance(declared_keys, Mapping):
            keys.update({str(key): str(value) for key, value in declared_keys.items()})
        items = document.data.get("items", [])
        if not isinstance(items, list):
            return
        verified = 0
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                continue
            location = SourceLocation(document.name, f"/items/{index}")
            identifier = str(item.get("id", ""))
            signer = str(item.get("signer", ""))
            key = keys.get(signer)
            if key is None:
                context.add(Finding("SIGNATURE_SIGNER_UNKNOWN", Severity.BLOCKER, "declaration signer is not in the local trust registry", location, subject=identifier, details={"signer": signer}))
                continue
            payload = self.canonical_payload(item)
            payload_digest = hashlib.sha256(payload).hexdigest()
            if payload_digest != item.get("payload_digest"):
                context.add(Finding("SIGNATURE_PAYLOAD_DIGEST_MISMATCH", Severity.BLOCKER, "declaration payload digest does not match canonical content", location, subject=identifier, details={"actual": payload_digest}))
                continue
            expected = hmac.new(key.encode("utf-8"), payload, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, str(item.get("signature", ""))):
                context.add(Finding("SIGNATURE_INVALID", Severity.BLOCKER, "declaration electronic signature is invalid", location, subject=identifier))
                continue
            verified += 1
        context.metrics["declarations_verified"] = verified

    @staticmethod
    def canonical_payload(item: Mapping[str, Any]) -> bytes:
        fields = {
            "id": item.get("id"),
            "application_id": item.get("application_id"),
            "agent_id": item.get("agent_id"),
            "tool_ids": sorted(str(value) for value in item.get("tool_ids", [])),
            "consent": item.get("consent"),
            "signature_algorithm": item.get("signature_algorithm"),
            "signer": item.get("signer"),
        }
        return json.dumps(fields, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
