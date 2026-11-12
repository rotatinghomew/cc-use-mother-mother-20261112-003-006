from __future__ import annotations

import copy
import unittest

from agentgate.bundle import BundleReader
from agentgate.domain import Decision, DocumentKind, ValidationContext
from agentgate.pipeline import CompilationPipeline
from agentgate.references.resolver import ReferenceGraph
from agentgate.schemas.normalizer import DocumentNormalizer

from tests.support import finding_codes, temporary_bundle


class NormalizationTests(unittest.TestCase):
    def test_version_10_fields_migrate_to_current_contract(self) -> None:
        def mutate(documents):
            identity = documents["identities.json"]
            identity["schema_version"] = "1.0"
            item = identity["items"][0]
            item["identity_code"] = item.pop("unique_code")
            item.pop("status")

        with temporary_bundle(mutate) as root:
            bundle = BundleReader(root).read()
            context = ValidationContext(bundle)
            DocumentNormalizer().normalize(context)
        identity = context.bundle.require(DocumentKind.IDENTITIES)
        self.assertEqual(identity.version, "2.0")
        self.assertEqual(identity.data["schema_version"], "2.0")
        self.assertEqual(identity.data["items"][0]["unique_code"], "AGT-ALPHA0001")
        self.assertEqual(identity.data["items"][0]["status"], "active")
        self.assertGreater(context.metrics["normalization_changes"], 0)

    def test_version_11_interaction_gets_category(self) -> None:
        def mutate(documents):
            interaction = documents["interactions.json"]
            interaction["schema_version"] = "1.1"
            interaction["items"][0].pop("category")

        with temporary_bundle(mutate) as root:
            bundle = BundleReader(root).read()
            context = ValidationContext(bundle)
            DocumentNormalizer().normalize(context)
        interaction = context.bundle.require(DocumentKind.INTERACTIONS)
        self.assertEqual(interaction.data["items"][0]["category"], "interaction")
        changes = context.artifacts["normalization"]
        interaction_log = next(item for item in changes if item["document"] == "interactions.json")
        self.assertTrue(interaction_log["changes"])

    def test_common_normalization_trims_and_deduplicates_lists(self) -> None:
        def mutate(documents):
            description = documents["descriptions.json"]["items"][0]
            description["owner"] = "  team:assistant-compliance  "
            description["data_destinations"] = ["local-device", "local-device", " vendor-cloud "]

        with temporary_bundle(mutate) as root:
            bundle = BundleReader(root).read()
            context = ValidationContext(bundle)
            DocumentNormalizer().normalize(context)
        description = context.bundle.require(DocumentKind.DESCRIPTIONS).data["items"][0]
        self.assertEqual(description["owner"], "team:assistant-compliance")
        self.assertEqual(description["data_destinations"], ["local-device", "vendor-cloud"])

    def test_permission_values_are_normalized(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"][0]["permission"] = "USER-DATA"
            documents["tools.json"]["items"][0]["maximum_permission"] = "USER-DATA"

        with temporary_bundle(mutate) as root:
            bundle = BundleReader(root).read()
            context = ValidationContext(bundle)
            DocumentNormalizer().normalize(context)
        self.assertEqual(context.bundle.require(DocumentKind.INTERACTIONS).data["items"][0]["permission"], "user_data")
        self.assertEqual(context.bundle.require(DocumentKind.TOOLS).data["items"][0]["maximum_permission"], "user_data")

    def test_normalization_does_not_change_already_normal_document(self) -> None:
        with temporary_bundle() as root:
            bundle = BundleReader(root).read()
            original = copy.deepcopy(bundle.require(DocumentKind.IDENTITIES).data)
            context = ValidationContext(bundle)
            DocumentNormalizer().normalize(context)
        self.assertEqual(original, context.bundle.require(DocumentKind.IDENTITIES).data)
        self.assertEqual(context.metrics["normalization_changes"], 0)


class ReferenceResolutionTests(unittest.TestCase):
    def test_valid_reciprocal_consent_scope_is_not_cycle_warning(self) -> None:
        with temporary_bundle() as root:
            result = CompilationPipeline().compile(root)
        self.assertNotIn("REFERENCE_CYCLE", finding_codes(result))
        self.assertIs(result.decision, Decision.ACCEPT)

    def test_missing_agent_reference_is_reported(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"][0]["agent_id"] = "agent-missing"

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        codes = finding_codes(result)
        self.assertIn("REFERENCE_TARGET_MISSING", codes)
        self.assertIn("POLICY_AGENT_UNKNOWN", codes)
        self.assertIn("POLICY_AGENT_MATERIAL_MISSING", codes)

    def test_missing_tool_reference_is_reported(self) -> None:
        def mutate(documents):
            documents["interactions.json"]["items"][0]["tool_ids"] = ["tool-missing"]

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("REFERENCE_TARGET_MISSING", finding_codes(result))
        self.assertIn("TRACE_TARGET_MISSING", finding_codes(result))

    def test_duplicate_identifier_within_kind_is_reported(self) -> None:
        def mutate(documents):
            duplicate = dict(documents["tools.json"]["items"][0])
            documents["tools.json"]["items"].append(duplicate)

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("REFERENCE_DUPLICATE_GLOBAL_ID", finding_codes(result))

    def test_cross_kind_identifier_collision_is_warning(self) -> None:
        def mutate(documents):
            documents["discovery.json"]["items"][0]["id"] = "tool-reserve"

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("CATALOG_CROSS_KIND_ID_COLLISION", finding_codes(result))

    def test_placeholder_identifier_is_error(self) -> None:
        def mutate(documents):
            documents["ota-plan.json"]["items"][0]["id"] = "sample-upgrade"

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("CATALOG_PLACEHOLDER_ID", finding_codes(result))

    def test_incomplete_per_agent_inventory_is_reported(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"] = []

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("CATALOG_AGENT_INVENTORY_INCOMPLETE", finding_codes(result))
        self.assertIn("POLICY_AGENT_MATERIAL_MISSING", finding_codes(result))

    def test_multiple_descriptions_violate_singleton_rule(self) -> None:
        def mutate(documents):
            duplicate = dict(documents["descriptions.json"]["items"][0])
            duplicate["id"] = "desc-alpha-secondary"
            documents["descriptions.json"]["items"].append(duplicate)

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("CATALOG_SINGLETON_VIOLATION", finding_codes(result))

    def test_graph_reachable_returns_transitive_targets(self) -> None:
        graph = ReferenceGraph()
        from agentgate.references.resolver import GraphEdge, GraphNode

        for identifier in ("a", "b", "c", "d"):
            graph.add_node(GraphNode("kind", identifier, "doc.json", "/", {}))
        graph.add_edge(GraphEdge(("kind", "a"), ("kind", "b"), "links", "doc.json", "/", True))
        graph.add_edge(GraphEdge(("kind", "b"), ("kind", "c"), "links", "doc.json", "/", True))
        self.assertEqual(graph.reachable(("kind", "a")), {("kind", "a"), ("kind", "b"), ("kind", "c")})
        self.assertEqual(graph.reachable(("kind", "d")), {("kind", "d")})

    def test_graph_cycle_detection_returns_closed_path(self) -> None:
        graph = ReferenceGraph()
        from agentgate.references.resolver import GraphEdge, GraphNode

        for identifier in ("a", "b", "c"):
            graph.add_node(GraphNode("kind", identifier, "doc.json", "/", {}))
        graph.add_edge(GraphEdge(("kind", "a"), ("kind", "b"), "links", "doc.json", "/", True))
        graph.add_edge(GraphEdge(("kind", "b"), ("kind", "c"), "links", "doc.json", "/", True))
        graph.add_edge(GraphEdge(("kind", "c"), ("kind", "a"), "links", "doc.json", "/", True))
        cycles = graph.cycles()
        self.assertEqual(len(cycles), 1)
        self.assertEqual(cycles[0][0], cycles[0][-1])

    def test_orphan_evidence_is_reported_as_unbound(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"].append({
                "id": "ev-orphan",
                "type": "control-test",
                "subject_kind": "tools",
                "subject_id": "tool-reserve",
                "assertion": "unused_assertion",
                "result": "pass",
                "artifact_digest": "a" * 64,
                "executed_at": "2026-11-01T08:00:00+00:00",
            })

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("EVIDENCE_UNBOUND", finding_codes(result))


if __name__ == "__main__":
    unittest.main()
