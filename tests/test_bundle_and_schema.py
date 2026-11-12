from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from agentgate.bundle import BundleReader
from agentgate.domain import Decision, DocumentKind
from agentgate.errors import BundleReadError
from agentgate.pipeline import CompilationPipeline

from tests.support import base_documents, encode_json, finding_codes, manifest_for, temporary_bundle, write_bundle


class BundleReaderTests(unittest.TestCase):
    def test_reads_complete_bundle_and_preserves_declared_kinds(self) -> None:
        with temporary_bundle() as root:
            bundle = BundleReader(root).read()
        self.assertEqual(bundle.bundle_id, "AGB-NORTHWIND-202611")
        self.assertEqual(bundle.revision, "r1")
        self.assertEqual(bundle.schema_version, "2.0")
        self.assertEqual(
            set(bundle.documents),
            {
                DocumentKind.IDENTITIES,
                DocumentKind.DESCRIPTIONS,
                DocumentKind.DISCOVERY,
                DocumentKind.INTERACTIONS,
                DocumentKind.TOOLS,
                DocumentKind.OTA_PLAN,
                DocumentKind.DECLARATIONS,
                DocumentKind.EVIDENCE,
                DocumentKind.BASELINE,
            },
        )
        self.assertTrue(all(document.digest for document in bundle.all_documents()))

    def test_rejects_missing_bundle_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(missing).read()
        self.assertIn("does not exist", str(raised.exception))

    def test_rejects_missing_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertIn("missing", str(raised.exception))

    def test_rejects_non_object_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            (root / "manifest.json").write_text("[]\n", encoding="utf-8")
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertIn("root must be an object", str(raised.exception))

    def test_rejects_invalid_utf8_document(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            documents = base_documents()
            manifest = manifest_for(documents)
            write_bundle(root, documents, manifest=manifest)
            (root / "identities.json").write_bytes(b"\xff\xfe")
            for entry in manifest["documents"]:
                if entry["path"] == "identities.json":
                    entry.pop("sha256", None)
            (root / "manifest.json").write_text(encode_json(manifest), encoding="utf-8")
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertIn("UTF-8", str(raised.exception))

    def test_rejects_invalid_json_with_location(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            documents = base_documents()
            manifest = manifest_for(documents)
            write_bundle(root, documents, manifest=manifest)
            (root / "tools.json").write_text('{"items": [}', encoding="utf-8")
            for entry in manifest["documents"]:
                if entry["path"] == "tools.json":
                    entry.pop("sha256", None)
            (root / "manifest.json").write_text(encode_json(manifest), encoding="utf-8")
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertIn("line", raised.exception.context)
        self.assertIn("column", raised.exception.context)

    def test_rejects_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            outside = Path(directory) / "outside.json"
            outside.write_text("{}", encoding="utf-8")
            manifest = {
                "bundle_id": "bundle",
                "revision": "r1",
                "schema_version": "2.0",
                "submitted_at": "2026-11-01T00:00:00+00:00",
                "documents": [{"kind": "identities", "path": "../outside.json"}],
            }
            (root / "manifest.json").write_text(encode_json(manifest), encoding="utf-8")
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertIn("escapes bundle root", str(raised.exception))

    def test_rejects_manifest_declaring_itself(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            root.mkdir()
            manifest = {
                "bundle_id": "bundle",
                "revision": "r1",
                "schema_version": "2.0",
                "submitted_at": "2026-11-01T00:00:00+00:00",
                "documents": [{"kind": "manifest", "path": "manifest.json"}],
            }
            (root / "manifest.json").write_text(encode_json(manifest), encoding="utf-8")
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertIn("cannot declare itself", str(raised.exception))

    def test_rejects_duplicate_document_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            documents = base_documents()
            manifest = manifest_for(documents)
            duplicate = dict(manifest["documents"][0])
            duplicate["path"] = "descriptions.json"
            manifest["documents"].append(duplicate)
            write_bundle(root, documents, manifest=manifest)
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertIn("duplicate document kind", str(raised.exception))

    def test_rejects_digest_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            documents = base_documents()
            manifest = manifest_for(documents)
            manifest["documents"][0]["sha256"] = "0" * 64
            write_bundle(root, documents, manifest=manifest)
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertEqual(raised.exception.context["expected"], "0" * 64)
        self.assertNotEqual(raised.exception.context["actual"], "0" * 64)

    def test_rejects_unknown_kind(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            documents = base_documents()
            manifest = manifest_for(documents)
            manifest["documents"][0]["kind"] = "unknown-material"
            write_bundle(root, documents, manifest=manifest)
            with self.assertRaises(BundleReadError) as raised:
                BundleReader(root).read()
        self.assertEqual(raised.exception.context["kind"], "unknown-material")


class SchemaAndCompilationTests(unittest.TestCase):
    def test_valid_bundle_is_accepted(self) -> None:
        with temporary_bundle() as root:
            result = CompilationPipeline().compile(root)
        self.assertIs(result.decision, Decision.ACCEPT)
        self.assertEqual(result.findings, ())
        self.assertEqual(result.metrics["coverage_ratio"], 1.0)
        self.assertEqual(result.metrics["declarations_verified"], 1)
        self.assertEqual(result.remediation_plan["tasks"], [])

    def test_unsupported_schema_version_stops_dependent_checks(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "bundle"
            documents = base_documents()
            manifest = manifest_for(documents)
            manifest["schema_version"] = "9.9"
            write_bundle(root, documents, manifest=manifest)
            result = CompilationPipeline().compile(root)
        codes = finding_codes(result)
        self.assertIn("SCHEMA_VERSION_UNSUPPORTED", codes)
        self.assertNotIn("MATRIX_TOOL_REQUIRED", codes)
        self.assertIs(result.decision, Decision.RETURN)

    def test_missing_required_document_is_blocker(self) -> None:
        def mutate(documents):
            documents.pop("tools.json")

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SCHEMA_DOCUMENT_MISSING", finding_codes(result))
        self.assertIs(result.decision, Decision.RETURN)

    def test_missing_required_field_is_reported_at_pointer(self) -> None:
        def mutate(documents):
            documents["identities.json"]["items"][0].pop("unique_code")

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        findings = [item for item in result.findings if item.code == "SCHEMA_REQUIRED_FIELD"]
        self.assertTrue(findings)
        self.assertEqual(findings[0].location.document, "identities.json")
        self.assertEqual(findings[0].location.pointer, "/items/0/unique_code")

    def test_invalid_identifier_pattern_is_rejected(self) -> None:
        def mutate(documents):
            documents["identities.json"]["items"][0]["id"] = "bad id with spaces"

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SCHEMA_FIELD_INVALID", finding_codes(result))

    def test_duplicate_item_id_is_reported(self) -> None:
        def mutate(documents):
            duplicate = dict(documents["discovery.json"]["items"][0])
            documents["discovery.json"]["items"].append(duplicate)

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SCHEMA_DUPLICATE_ID", finding_codes(result))
        self.assertIn("POLICY_DISCOVERY_DUPLICATE", finding_codes(result))

    def test_non_array_items_is_rejected(self) -> None:
        def mutate(documents):
            documents["descriptions.json"]["items"] = {"id": "desc-alpha"}

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SCHEMA_ITEMS_TYPE", finding_codes(result))

    def test_empty_required_collection_is_rejected(self) -> None:
        def mutate(documents):
            documents["identities.json"]["items"] = []

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SCHEMA_ITEMS_MINIMUM", finding_codes(result))

    def test_invalid_iso_datetime_is_rejected(self) -> None:
        def mutate(documents):
            documents["evidence.json"]["items"][0]["executed_at"] = "not-a-time"

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        self.assertIn("SCHEMA_CUSTOM_RULE", finding_codes(result))
        self.assertIn("EVIDENCE_TIME_INVALID", finding_codes(result))

    def test_missing_manifest_digests_produce_warnings(self) -> None:
        with temporary_bundle(include_digests=False) as root:
            result = CompilationPipeline().compile(root)
        warnings = [item for item in result.findings if item.code == "INTEGRITY_DIGEST_NOT_DECLARED"]
        self.assertEqual(len(warnings), 9)
        self.assertIs(result.decision, Decision.MANUAL_REVIEW)

    def test_compilation_result_serializes_remediation(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["requires_confirmation"] = False

        with temporary_bundle(mutate) as root:
            result = CompilationPipeline().compile(root)
        encoded = result.as_dict()
        self.assertEqual(encoded["bundle_id"], result.bundle_id)
        self.assertEqual(encoded["decision"], "return")
        self.assertEqual(encoded["remediation_plan"]["format"], "agent-gate-remediation-plan/v1")
        self.assertGreater(encoded["remediation_plan"]["summary"]["task_count"], 0)


if __name__ == "__main__":
    unittest.main()
