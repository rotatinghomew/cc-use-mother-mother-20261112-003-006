from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from agentgate.commands.output import AtomicOutputWriter
from agentgate.pipeline import CompilationPipeline
from agentgate.review import ReviewStore

from tests.support import base_documents, encode_json, finding_codes, manifest_for, run_cli, temporary_bundle, write_bundle


class AtomicOutputWriterTests(unittest.TestCase):
    def test_writes_sorted_pretty_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = AtomicOutputWriter(directory)
            paths = writer.write({"result.json": {"z": 1, "a": 2}})
            payload = paths[0].read_text(encoding="utf-8")
        self.assertTrue(payload.endswith("\n"))
        self.assertLess(payload.index('"a"'), payload.index('"z"'))

    def test_replaces_existing_file_atomically(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "result.json"
            target.write_text('{"old": true}\n', encoding="utf-8")
            AtomicOutputWriter(root).write({"result.json": {"new": True}})
            loaded = json.loads(target.read_text(encoding="utf-8"))
            temporary = list(root.glob(".*.tmp"))
        self.assertEqual(loaded, {"new": True})
        self.assertEqual(temporary, [])

    def test_rejects_parent_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = AtomicOutputWriter(directory)
            with self.assertRaises(ValueError):
                writer.write({"../escape.json": {}})

    def test_rejects_non_json_name(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            writer = AtomicOutputWriter(directory)
            with self.assertRaises(ValueError):
                writer.write({"result.txt": {}})


class ReviewStoreTests(unittest.TestCase):
    def test_initialize_creates_expected_tables(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "review.sqlite3"
            store = ReviewStore(path)
            store.initialize()
            with sqlite3.connect(path) as connection:
                names = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertTrue({"bundles", "findings", "finding_events", "artifacts"}.issubset(names))

    def test_compile_persists_all_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "review.sqlite3"
            with temporary_bundle() as root:
                result = CompilationPipeline(store_path=store_path).compile(root)
            store = ReviewStore(store_path)
            for name in ("return-list", "review-package", "baseline-snapshot", "remediation-plan"):
                artifact = store.load_artifact(result.bundle_id, result.revision, name)
                self.assertIsNotNone(artifact, name)

    def test_finding_history_records_detection_once(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["requires_confirmation"] = False

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "review.sqlite3"
            with temporary_bundle(mutate) as root:
                first = CompilationPipeline(store_path=store_path).compile(root)
                second = CompilationPipeline(store_path=store_path).compile(root)
            fingerprint = next(item.fingerprint for item in first.findings if item.code == "MATRIX_CONFIRMATION_MISSING")
            history = ReviewStore(store_path).history(first.bundle_id, fingerprint)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["event_type"], "detected")
        self.assertEqual(history[0]["state"], "open")
        self.assertEqual(first.bundle_id, second.bundle_id)

    def test_disappeared_finding_is_marked_fixed(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["requires_confirmation"] = False

        with tempfile.TemporaryDirectory() as directory:
            store_path = Path(directory) / "review.sqlite3"
            with temporary_bundle(mutate, revision="r1") as root:
                first = CompilationPipeline(store_path=store_path).compile(root)
            fingerprint = next(item.fingerprint for item in first.findings if item.code == "MATRIX_CONFIRMATION_MISSING")
            with temporary_bundle(revision="r2") as root:
                CompilationPipeline(store_path=store_path).compile(root)
            history = ReviewStore(store_path).history(first.bundle_id, fingerprint)
        self.assertEqual(history[-1]["event_type"], "not_reproduced")
        self.assertEqual(history[-1]["state"], "fixed")

    def test_unknown_artifact_returns_none(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ReviewStore(Path(directory) / "review.sqlite3")
            self.assertIsNone(store.load_artifact("missing", "r1", "return-list"))

    def test_empty_history_returns_empty_list(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = ReviewStore(Path(directory) / "review.sqlite3")
            self.assertEqual(store.history("missing", "fingerprint"), [])


class CommandLineTests(unittest.TestCase):
    def test_compile_command_writes_three_outputs_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            store = Path(directory) / "review.sqlite3"
            with temporary_bundle() as root:
                completed = run_cli(["compile", str(root), "--output", str(output), "--store", str(store), "--summary"])
            summary = json.loads(completed.stdout)
            names = {path.name for path in output.iterdir()}
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(summary["decision"], "accept")
        self.assertEqual(names, {"return-list.json", "review-package.json", "remediation-plan.json"})

    def test_compile_command_returns_one_for_rejected_submission(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["requires_confirmation"] = False

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            with temporary_bundle(mutate) as root:
                completed = run_cli(["compile", str(root), "--output", str(output), "--summary"])
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(json.loads(completed.stdout)["decision"], "return")

    def test_compile_command_reports_bundle_read_error_as_json(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing"
            output = Path(directory) / "output"
            completed = run_cli(["compile", str(missing), "--output", str(output)])
        self.assertEqual(completed.returncode, 3)
        error = json.loads(completed.stderr)
        self.assertIn("does not exist", error["error"])

    def test_artifact_command_reads_remediation_plan(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "review.sqlite3"
            output = Path(directory) / "output"
            with temporary_bundle() as root:
                compiled = run_cli(["compile", str(root), "--output", str(output), "--store", str(store), "--summary"])
            summary = json.loads(compiled.stdout)
            artifact = run_cli([
                "artifact",
                "--store", str(store),
                "--bundle-id", summary["bundle_id"],
                "--revision", summary["revision"],
                "--name", "remediation-plan",
            ])
        self.assertEqual(artifact.returncode, 0, artifact.stderr)
        self.assertEqual(json.loads(artifact.stdout)["format"], "agent-gate-remediation-plan/v1")

    def test_artifact_command_returns_one_when_missing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "review.sqlite3"
            result = run_cli([
                "artifact",
                "--store", str(store),
                "--bundle-id", "missing",
                "--revision", "r1",
                "--name", "return-list",
            ])
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads(result.stderr)["error"], "artifact not found")

    def test_history_command_reads_finding_events(self) -> None:
        def mutate(documents):
            documents["tools.json"]["items"][0]["requires_confirmation"] = False

        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "review.sqlite3"
            output = Path(directory) / "output"
            with temporary_bundle(mutate) as root:
                compiled = run_cli(["compile", str(root), "--output", str(output), "--store", str(store), "--summary"])
            summary = json.loads(compiled.stdout)
            review = json.loads((output / "review-package.json").read_text(encoding="utf-8"))
            fingerprint = next(item["fingerprint"] for item in review["findings"] if item["code"] == "MATRIX_CONFIRMATION_MISSING")
            history = run_cli([
                "history",
                "--store", str(store),
                "--bundle-id", summary["bundle_id"],
                "--fingerprint", fingerprint,
            ])
        self.assertEqual(history.returncode, 0, history.stderr)
        self.assertEqual(json.loads(history.stdout)[0]["event_type"], "detected")

    def test_history_command_returns_one_for_unknown_fingerprint(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            store = Path(directory) / "review.sqlite3"
            history = run_cli([
                "history",
                "--store", str(store),
                "--bundle-id", "missing",
                "--fingerprint", "0" * 64,
            ])
        self.assertEqual(history.returncode, 1)
        self.assertEqual(json.loads(history.stdout), [])


if __name__ == "__main__":
    unittest.main()
