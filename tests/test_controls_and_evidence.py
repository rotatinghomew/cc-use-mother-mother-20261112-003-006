from __future__ import annotations

import unittest

from agentgate.domain import Decision
from agentgate.pipeline import CompilationPipeline

from tests.support import evidence, finding_codes, findings_by_code, sign_declarations, temporary_bundle


class CapabilityMatrixTests(unittest.TestCase):
    def compile(self, mutator):
        with temporary_bundle(mutator) as root:
            return CompilationPipeline().compile(root)

    def test_sensitive_capability_requires_declared_approval(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"][0]["approval_required"] = False

        result = self.compile(mutate)
        self.assertIn("MATRIX_APPROVAL_NOT_DECLARED", finding_codes(result))
        self.assertIs(result.decision, Decision.RETURN)

    def test_sensitive_capability_requires_declared_audit(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"][0]["audit_required"] = False

        result = self.compile(mutate)
        self.assertIn("MATRIX_AUDIT_NOT_DECLARED", finding_codes(result))

    def test_tool_call_requires_tool(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"][0]["tool_ids"] = []

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_TOOL_REQUIRED", codes)
        self.assertIn("TRACE_CAPABILITY_TOOL_PATH_MISSING", codes)

    def test_tool_grant_must_cover_requested_permission(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["maximum_permission"] = "device"

        result = self.compile(mutate)
        finding = findings_by_code(result, "MATRIX_GRANT_TOO_LOW")[0]
        self.assertEqual(finding.details["requested"], "user_data")
        self.assertEqual(finding.details["granted"], "device")

    def test_sensitive_tool_requires_confirmation(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["requires_confirmation"] = False

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_CONFIRMATION_MISSING", codes)
        self.assertIn("POLICY_TOOL_CONFIRMATION_REQUIRED", codes)

    def test_sensitive_tool_requires_audit_record(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["writes_audit_record"] = False

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_AUDIT_RECORD_MISSING", codes)
        self.assertIn("POLICY_TOOL_AUDIT_REQUIRED", codes)

    def test_sensitive_tool_requires_signed_declaration_reference(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["declaration_ids"] = []

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_DECLARATION_MISSING", codes)
        self.assertIn("POLICY_TOOL_DECLARATION_REQUIRED", codes)

    def test_capability_and_tool_agent_must_match(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["agent_id"] = "agent-other"

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_AGENT_MISMATCH", codes)
        self.assertIn("TRACE_AGENT_MISMATCH", codes)

    def test_capability_and_tool_operation_must_match(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["operation"] = "read-itinerary"

        result = self.compile(mutate)
        self.assertIn("MATRIX_OPERATION_MISMATCH", finding_codes(result))

    def test_declaration_must_cover_tool(self) -> None:
        def mutate(documents):
            documents["declarations.json"]["items"][0]["tool_ids"] = ["tool-other"]

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_DECLARATION_SCOPE_MISMATCH", codes)
        self.assertIn("MATRIX_DECLARATION_UNKNOWN_TOOL", codes)

    def test_declaration_agent_must_match_capability(self) -> None:
        def mutate(documents):
            documents["declarations.json"]["items"][0]["agent_id"] = "agent-other"

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_DECLARATION_AGENT_MISMATCH", codes)
        self.assertIn("TRACE_AGENT_MISMATCH", codes)

    def test_declaration_must_express_active_consent(self) -> None:
        def mutate(documents):
            documents["declarations.json"]["items"][0]["consent"] = False

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_DECLARATION_NO_CONSENT", codes)
        self.assertIn("POLICY_DECLARATION_CONSENT_REQUIRED", codes)

    def test_unused_tool_is_manual_review_warning(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"].append({
                "id": "tool-unused",
                "agent_id": "agent-alpha",
                "operation": "read-weather",
                "maximum_permission": "device",
                "requires_confirmation": False,
                "writes_audit_record": False,
                "declaration_ids": [],
            })

        result = self.compile(mutate)
        self.assertIn("MATRIX_UNUSED_TOOL", finding_codes(result))

    def test_conflicting_duplicate_operation_is_error(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"].append({
                "id": "cap-reserve-secondary",
                "agent_id": "agent-alpha",
                "operation": "reserve-itinerary",
                "category": "tool_call",
                "permission": "system",
                "approval_required": True,
                "audit_required": True,
                "tool_ids": ["tool-reserve"],
                "evidence_ids": ["ev-cap-auth", "ev-cap-audit"],
            })

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("MATRIX_OPERATION_CONFLICT", codes)
        self.assertIn("POLICY_OPERATION_DUPLICATE", codes)

    def test_privileged_capability_requires_declared_evidence(self) -> None:
        def mutate(documents):
            capability = documents["interactions.json"]["items"][0]
            capability["permission"] = "system"
            capability["evidence_ids"] = []
            documents["tools.json"]["items"][0]["maximum_permission"] = "system"

        result = self.compile(mutate)
        self.assertIn("MATRIX_PRIVILEGED_EVIDENCE_MISSING", finding_codes(result))

    def test_discovery_capability_cannot_request_user_data(self) -> None:
        def mutate(documents):
            capability = documents["interactions.json"]["items"][0]
            capability["category"] = "discovery"
            capability["permission"] = "user_data"

        result = self.compile(mutate)
        self.assertIn("MATRIX_DISCOVERY_OVERPRIVILEGED", finding_codes(result))

    def test_invalid_permission_is_reported_without_crash(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"][0]["permission"] = "root-of-everything"

        result = self.compile(mutate)
        self.assertIn("MATRIX_PERMISSION_INVALID", finding_codes(result))

    def test_invalid_tool_permission_is_reported_without_crash(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["maximum_permission"] = "root-of-everything"

        result = self.compile(mutate)
        self.assertIn("MATRIX_TOOL_PERMISSION_INVALID", finding_codes(result))


class EvidenceCoverageTests(unittest.TestCase):
    def compile(self, mutator):
        with temporary_bundle(mutator) as root:
            return CompilationPipeline().compile(root)

    def test_missing_authorization_evidence_is_error(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"] = [
                item for item in documents["evidence.json"]["items"] if item["id"] != "ev-cap-auth"
            ]
            documents["interactions.json"]["items"][0]["evidence_ids"].remove("ev-cap-auth")

        result = self.compile(mutate)
        finding = findings_by_code(result, "EVIDENCE_COVERAGE_MISSING")[0]
        self.assertEqual(finding.subject, "cap-reserve")

    def test_failed_evidence_does_not_satisfy_requirement(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"][0]["result"] = "fail"

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("EVIDENCE_REPORTED_FAILURE", codes)
        self.assertIn("EVIDENCE_COVERAGE_UNSATISFIED", codes)

    def test_inconclusive_evidence_is_warning_and_unsatisfied(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"][0]["result"] = "inconclusive"

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("EVIDENCE_INCONCLUSIVE", codes)
        self.assertIn("EVIDENCE_COVERAGE_UNSATISFIED", codes)

    def test_stale_evidence_is_not_counted_as_passing(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"][0]["executed_at"] = "2020-01-01T00:00:00+00:00"

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("EVIDENCE_STALE", codes)
        self.assertIn("EVIDENCE_COVERAGE_UNSATISFIED", codes)

    def test_future_evidence_is_rejected(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"][0]["executed_at"] = "2099-01-01T00:00:00+00:00"

        result = self.compile(mutate)
        self.assertIn("EVIDENCE_TIME_IN_FUTURE", finding_codes(result))

    def test_short_digest_is_rejected(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"][0]["artifact_digest"] = "abcd"

        result = self.compile(mutate)
        self.assertIn("EVIDENCE_DIGEST_INVALID", finding_codes(result))

    def test_declared_evidence_subject_must_match_capability(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"][0]["subject_id"] = "cap-other"

        result = self.compile(mutate)
        self.assertIn("EVIDENCE_SUBJECT_MISMATCH", finding_codes(result))

    def test_artifact_reuse_across_assertions_is_warning(self) -> None:
        def mutate(documents):
            first = documents["evidence.json"]["items"][0]
            documents["evidence.json"]["items"][1]["artifact_digest"] = first["artifact_digest"]

        result = self.compile(mutate)
        self.assertIn("EVIDENCE_ARTIFACT_REUSED", finding_codes(result))

    def test_ota_scheme_must_be_submitted(self) -> None:
        def mutate(documents):
            documents["ota-plan.json"]["items"][0]["scheme_submitted"] = False

        result = self.compile(mutate)
        self.assertIn("OTA_SCHEME_NOT_SUBMITTED", finding_codes(result))

    def test_ota_completion_report_must_be_required(self) -> None:
        def mutate(documents):
            documents["ota-plan.json"]["items"][0]["completion_report_required"] = False

        result = self.compile(mutate)
        self.assertIn("OTA_COMPLETION_REPORT_NOT_REQUIRED", finding_codes(result))

    def test_ota_assessment_must_cover_all_categories(self) -> None:
        def mutate(documents):
            documents["ota-plan.json"]["items"][0]["impact_assessment"].pop("rollback")

        result = self.compile(mutate)
        codes = finding_codes(result)
        self.assertIn("OTA_ASSESSMENT_INCOMPLETE", codes)
        self.assertIn("POLICY_OTA_ROLLBACK_UNDEFINED", codes)

    def test_unbound_evidence_is_warning(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"].append(
                evidence("ev-extra", "control-test", "tools", "tool-reserve", "tool_loaded")
            )

        result = self.compile(mutate)
        self.assertIn("EVIDENCE_UNBOUND", finding_codes(result))


class PolicyAndSignatureTests(unittest.TestCase):
    def compile(self, mutator):
        with temporary_bundle(mutator) as root:
            return CompilationPipeline().compile(root)

    def test_unknown_signer_is_blocker(self) -> None:
        def mutate(documents):
            documents["declarations.json"]["items"][0]["signer"] = "unknown-key"

        result = self.compile(mutate)
        self.assertIn("SIGNATURE_SIGNER_UNKNOWN", finding_codes(result))

    def test_payload_digest_mismatch_is_blocker(self) -> None:
        def mutate(documents):
            documents["declarations.json"]["items"][0]["payload_digest"] = "0" * 64

        with temporary_bundle(mutate, resign=False) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SIGNATURE_PAYLOAD_DIGEST_MISMATCH", finding_codes(result))

    def test_invalid_signature_is_blocker(self) -> None:
        def mutate(documents):
            item = documents["declarations.json"]["items"][0]
            sign_declarations(documents)
            item["signature"] = "0" * 64

        with temporary_bundle(mutate, resign=False) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SIGNATURE_INVALID", finding_codes(result))

    def test_forbidden_operation_is_blocker(self) -> None:
        def mutate(documents):
            operation = "silent-escalation-and-reserve"
            documents["interactions.json"]["items"][0]["operation"] = operation
            documents["tools.json"]["items"][0]["operation"] = operation

        result = self.compile(mutate)
        self.assertIn("POLICY_OPERATION_FORBIDDEN", finding_codes(result))

    def test_unclassified_destination_is_error(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"][0]["data_destinations"] = ["mystery-cloud"]

        result = self.compile(mutate)
        self.assertIn("POLICY_DESTINATION_UNCLASSIFIED", finding_codes(result))

    def test_unroutable_owner_is_warning(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"][0]["owner"] = "nobody"

        result = self.compile(mutate)
        self.assertIn("POLICY_OWNER_UNROUTABLE", finding_codes(result))

    def test_brief_purpose_is_warning(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"][0]["purpose"] = "Books trips."

        result = self.compile(mutate)
        self.assertIn("POLICY_PURPOSE_TOO_BRIEF", finding_codes(result))

    def test_unknown_discovery_channel_is_error(self) -> None:
        def mutate(documents):
            documents["discovery.json"]["items"][0]["channel"] = "hidden-broadcast"

        result = self.compile(mutate)
        self.assertIn("POLICY_DISCOVERY_CHANNEL_UNKNOWN", finding_codes(result))

    def test_unbounded_discovery_is_warning(self) -> None:
        def mutate(documents):
            documents["discovery.json"]["items"][0]["audiences"] = ["all"]

        result = self.compile(mutate)
        self.assertIn("POLICY_DISCOVERY_UNBOUNDED", finding_codes(result))

    def test_unchanged_ota_version_is_error(self) -> None:
        def mutate(documents):
            documents["ota-plan.json"]["items"][0]["to_version"] = "1.0.0"

        result = self.compile(mutate)
        self.assertIn("POLICY_OTA_VERSION_UNCHANGED", finding_codes(result))

    def test_third_party_destination_requires_declaration(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"][0]["data_destinations"] = ["declared-third-party:app-missing"]

        result = self.compile(mutate)
        self.assertIn("TRACE_DESTINATION_DECLARATION_MISSING", finding_codes(result))


if __name__ == "__main__":
    unittest.main()
