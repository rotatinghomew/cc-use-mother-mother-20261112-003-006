from __future__ import annotations

import copy
import unittest

from agentgate.diff import BaselineDiffer
from agentgate.domain import FindingState, Severity
from agentgate.pipeline import CompilationPipeline
from agentgate.remediation import RemediationPlanBuilder
from agentgate.review import FindingManager

from tests.support import finding_codes, make_context, sample_finding, temporary_bundle


class BaselineChangeTests(unittest.TestCase):
    def compile_without_refresh(self, mutator):
        with temporary_bundle(mutator, refresh_baseline=False) as root:
            return CompilationPipeline().compile(root)

    def test_permission_change_is_high_risk(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"][0]["permission"] = "system"
            documents["tools.json"]["items"][0]["maximum_permission"] = "system"

        result = self.compile_without_refresh(mutate)
        changes = result.review_package["baseline_diff"]
        interaction = next(item for item in changes if item["kind"] == "interactions")
        self.assertEqual(interaction["risk"], "high")
        self.assertIn("permission", interaction["changed_fields"])
        self.assertIn("DIFF_HIGH_RISK_CHANGE", finding_codes(result))

    def test_unique_identity_code_change_is_blocker(self) -> None:
        def mutate(documents):
            documents["identities.json"]["items"][0]["unique_code"] = "AGT-ALPHA9999"

        result = self.compile_without_refresh(mutate)
        self.assertIn("DIFF_UNIQUE_CODE_CHANGED", finding_codes(result))

    def test_added_capability_is_medium_or_high_review(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"].append({
                "id": "cap-discover-weather",
                "agent_id": "agent-alpha",
                "operation": "discover-weather",
                "category": "discovery",
                "permission": "device",
                "approval_required": False,
                "audit_required": False,
                "tool_ids": [],
                "evidence_ids": [],
            })

        result = self.compile_without_refresh(mutate)
        self.assertTrue({"DIFF_REVIEW_REQUIRED", "DIFF_HIGH_RISK_CHANGE"} & finding_codes(result))

    def test_removed_tool_is_high_risk(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"] = []

        result = self.compile_without_refresh(mutate)
        changes = result.review_package["baseline_diff"]
        removed = next(item for item in changes if item["kind"] == "tools")
        self.assertEqual(removed["change_type"], "removed")
        self.assertEqual(removed["risk"], "high")

    def test_missing_ota_plan_stops_before_change_analysis(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"][0]["data_destinations"].append("vendor-analytics")
            documents.pop("ota-plan.json")

        result = self.compile_without_refresh(mutate)
        self.assertIn("SCHEMA_DOCUMENT_MISSING", finding_codes(result))
        self.assertNotIn("DIFF_OTA_PLAN_MISSING", finding_codes(result))

    def test_ota_impact_gap_is_error(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"][0]["data_destinations"].append("vendor-analytics")
            documents["ota-plan.json"]["items"][0]["impact_assessment"].pop("capabilities")

        result = self.compile_without_refresh(mutate)
        self.assertIn("DIFF_OTA_IMPACT_GAP", finding_codes(result))

    def test_snapshot_omits_evidence_baseline_and_closures(self) -> None:
        with temporary_bundle() as root:
            pipeline = CompilationPipeline()
            result = pipeline.compile(root)
            from agentgate.bundle import BundleReader
            from agentgate.domain import ValidationContext
            context = ValidationContext(BundleReader(root).read())
            snapshot = pipeline.differ.snapshot(context)
        self.assertEqual(result.review_package["baseline_diff"], [])
        kinds = {item["kind"] for item in snapshot["items"]}
        self.assertNotIn("evidence", kinds)
        self.assertNotIn("baseline", kinds)
        self.assertNotIn("closures", kinds)

    def test_changed_fields_are_sorted(self) -> None:
        differ = BaselineDiffer()
        fields = differ._changed_fields({"z": 1, "a": 1}, {"z": 2, "b": 1})
        self.assertEqual(fields, ("a", "b", "z"))

    def test_fingerprint_is_deterministic_for_mapping_order(self) -> None:
        differ = BaselineDiffer()
        first = differ._fingerprint({"a": 1, "b": 2})
        second = differ._fingerprint({"b": 2, "a": 1})
        self.assertEqual(first, second)


class FindingAndRemediationTests(unittest.TestCase):
    def finalized_context(self, findings):
        context = make_context(findings)
        FindingManager().finalize(context)
        return context

    def test_finding_fingerprint_ignores_message_text(self) -> None:
        manager = FindingManager()
        first = sample_finding("MATRIX_CONFIRMATION_MISSING")
        second = sample_finding("MATRIX_CONFIRMATION_MISSING")
        second.message = "different explanatory wording"
        self.assertEqual(manager.fingerprint(first), manager.fingerprint(second))

    def test_finding_manager_deduplicates_and_keeps_more_severe(self) -> None:
        warning = sample_finding("POLICY_TOOL_CONFIRMATION_REQUIRED", Severity.WARNING)
        blocker = sample_finding("POLICY_TOOL_CONFIRMATION_REQUIRED", Severity.BLOCKER)
        context = self.finalized_context([warning, blocker])
        self.assertEqual(len(context.findings), 1)
        self.assertIs(context.findings[0].severity, Severity.BLOCKER)

    def test_verified_and_waived_findings_are_not_actionable(self) -> None:
        verified = sample_finding("MATRIX_CONFIRMATION_MISSING")
        verified.state = FindingState.VERIFIED
        waived = sample_finding("POLICY_OWNER_UNROUTABLE", Severity.WARNING)
        waived.state = FindingState.WAIVED
        context = self.finalized_context([verified, waived])
        plan = RemediationPlanBuilder().build(context)
        self.assertEqual(plan["tasks"], [])

    def test_schema_task_precedes_reference_and_matrix_tasks(self) -> None:
        findings = [
            sample_finding("SCHEMA_REQUIRED_FIELD", Severity.ERROR, document="interactions.json"),
            sample_finding("REFERENCE_TARGET_MISSING", Severity.ERROR, document="interactions.json"),
            sample_finding("MATRIX_CONFIRMATION_MISSING", Severity.BLOCKER, document="interactions.json"),
        ]
        context = self.finalized_context(findings)
        plan = RemediationPlanBuilder().build(context)
        by_code = {task["finding_codes"][0].split("_", 1)[0]: task for task in plan["tasks"]}
        self.assertLess(by_code["SCHEMA"]["wave"], by_code["REFERENCE"]["wave"])
        self.assertLess(by_code["REFERENCE"]["wave"], by_code["MATRIX"]["wave"])
        self.assertIn(by_code["SCHEMA"]["task_id"], by_code["REFERENCE"]["depends_on"])

    def test_evidence_task_precedes_closure_task(self) -> None:
        findings = [
            sample_finding("EVIDENCE_COVERAGE_MISSING", Severity.ERROR, document="evidence.json"),
            sample_finding("CLOSURE_EVIDENCE_REQUIRED", Severity.ERROR, document="closures.json"),
        ]
        context = self.finalized_context(findings)
        plan = RemediationPlanBuilder().build(context)
        by_prefix = {task["finding_codes"][0].split("_", 1)[0]: task for task in plan["tasks"]}
        self.assertLess(by_prefix["EVIDENCE"]["wave"], by_prefix["CLOSURE"]["wave"])

    def test_blocker_task_requires_independent_signoff(self) -> None:
        context = self.finalized_context([sample_finding("SIGNATURE_INVALID", Severity.BLOCKER, document="declarations.json")])
        task = RemediationPlanBuilder().build(context)["tasks"][0]
        self.assertIn("independent reviewer sign-off", task["required_evidence"])
        self.assertEqual(task["priority"], 1)

    def test_control_task_requires_negative_path_regression(self) -> None:
        context = self.finalized_context([sample_finding("MATRIX_AUDIT_RECORD_MISSING", Severity.ERROR)])
        task = RemediationPlanBuilder().build(context)["tasks"][0]
        self.assertIn("negative-path regression test", task["required_evidence"])

    def test_reference_task_requires_machine_readable_comparison(self) -> None:
        context = self.finalized_context([sample_finding("REFERENCE_TARGET_MISSING", Severity.ERROR)])
        task = RemediationPlanBuilder().build(context)["tasks"][0]
        self.assertIn("machine-readable comparison artifact", task["required_evidence"])

    def test_missing_identifiers_are_added_to_required_actions(self) -> None:
        finding = sample_finding("SCHEMA_DOCUMENT_MISSING", Severity.BLOCKER, details={"missing": ["tools", "evidence"]})
        context = self.finalized_context([finding])
        task = RemediationPlanBuilder().build(context)["tasks"][0]
        self.assertTrue(any("evidence, tools" in action for action in task["required_actions"]))

    def test_expected_actual_details_are_added_to_actions(self) -> None:
        finding = sample_finding("MATRIX_GRANT_TOO_LOW", Severity.ERROR, details={"expected": "system", "actual": "device"})
        context = self.finalized_context([finding])
        task = RemediationPlanBuilder().build(context)["tasks"][0]
        self.assertTrue(any("expected 'system'" in action for action in task["required_actions"]))

    def test_integrity_digest_is_deterministic(self) -> None:
        findings = [sample_finding("MATRIX_CONFIRMATION_MISSING", Severity.BLOCKER)]
        first_context = self.finalized_context(copy.deepcopy(findings))
        second_context = self.finalized_context(copy.deepcopy(findings))
        first = RemediationPlanBuilder().build(first_context)["integrity"]["digest"]
        second = RemediationPlanBuilder().build(second_context)["integrity"]["digest"]
        self.assertEqual(first, second)

    def test_summary_counts_owners_priorities_and_waves(self) -> None:
        findings = [
            sample_finding("SCHEMA_REQUIRED_FIELD", Severity.ERROR, document="interactions.json"),
            sample_finding("MATRIX_CONFIRMATION_MISSING", Severity.BLOCKER, document="interactions.json"),
            sample_finding("POLICY_OWNER_UNROUTABLE", Severity.WARNING, document="descriptions.json", subject="desc-alpha"),
        ]
        context = self.finalized_context(findings)
        summary = RemediationPlanBuilder().build(context)["summary"]
        self.assertEqual(summary["task_count"], 3)
        self.assertGreaterEqual(summary["wave_count"], 2)
        self.assertEqual(summary["finding_count"], 3)
        self.assertIn("submission-contract", summary["owner_counts"])
        self.assertIn("1", summary["priority_counts"])

    def test_execution_analysis_exposes_parallel_waves_and_workload(self) -> None:
        findings = [
            sample_finding("SCHEMA_REQUIRED_FIELD", Severity.ERROR, document="interactions.json"),
            sample_finding("REFERENCE_TARGET_MISSING", Severity.ERROR, document="interactions.json"),
            sample_finding("POLICY_OWNER_UNROUTABLE", Severity.WARNING, document="descriptions.json", subject="desc-alpha"),
        ]
        context = self.finalized_context(findings)
        analysis = RemediationPlanBuilder().build(context)["execution_analysis"]
        self.assertTrue(analysis["ready_task_ids"])
        self.assertTrue(analysis["blocked_task_ids"])
        self.assertGreaterEqual(len(analysis["parallel_waves"]), 2)
        self.assertIn("submission-contract", analysis["owner_workload"])
        self.assertTrue(analysis["closure_ready"])

    def test_critical_path_prefers_dependency_chain_with_higher_risk(self) -> None:
        findings = [
            sample_finding("SCHEMA_REQUIRED_FIELD", Severity.BLOCKER, document="interactions.json"),
            sample_finding("REFERENCE_TARGET_MISSING", Severity.ERROR, document="interactions.json"),
            sample_finding("MATRIX_CONFIRMATION_MISSING", Severity.BLOCKER, document="interactions.json"),
            sample_finding("POLICY_OWNER_UNROUTABLE", Severity.WARNING, document="descriptions.json", subject="desc-alpha"),
        ]
        context = self.finalized_context(findings)
        plan = RemediationPlanBuilder().build(context)
        critical = plan["execution_analysis"]["critical_path_task_ids"]
        prefixes = []
        by_id = {task["task_id"]: task for task in plan["tasks"]}
        for task_id in critical:
            prefixes.append(by_id[task_id]["finding_codes"][0].split("_", 1)[0])
        self.assertEqual(prefixes, ["SCHEMA", "REFERENCE", "MATRIX"])
        self.assertGreater(plan["execution_analysis"]["critical_path_risk_score"], 200)


if __name__ == "__main__":
    unittest.main()
