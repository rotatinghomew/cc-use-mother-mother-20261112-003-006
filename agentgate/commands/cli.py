from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence

from ..diff import BaselineDiffer
from ..domain import Decision, ValidationContext
from ..errors import AgentGateError
from ..pipeline import CompilationPipeline
from ..review import ReviewStore
from .output import AtomicOutputWriter


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(prog="agentgate", description="Compile and review preinstalled-agent network submission materials")
    subcommands = value.add_subparsers(dest="command", required=True)
    compile_command = subcommands.add_parser("compile", help="compile a declaration bundle")
    compile_command.add_argument("bundle", help="directory containing manifest.json and declared documents")
    compile_command.add_argument("--output", required=True, help="directory for return-list.json and review-package.json")
    compile_command.add_argument("--store", help="SQLite review state database")
    compile_command.add_argument("--summary", action="store_true", help="write a concise JSON summary to stdout")
    history = subcommands.add_parser("history", help="show a finding lifecycle from the review store")
    history.add_argument("--store", required=True)
    history.add_argument("--bundle-id", required=True)
    history.add_argument("--fingerprint", required=True)
    artifact = subcommands.add_parser("artifact", help="read a compiled artifact from the review store")
    artifact.add_argument("--store", required=True)
    artifact.add_argument("--bundle-id", required=True)
    artifact.add_argument("--revision", required=True)
    artifact.add_argument("--name", choices=("return-list", "review-package", "baseline-snapshot", "remediation-plan"), required=True)
    return value


def main(argv: Sequence[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        if arguments.command == "compile":
            return _compile(arguments)
        if arguments.command == "history":
            return _history(arguments)
        if arguments.command == "artifact":
            return _artifact(arguments)
        raise AssertionError(arguments.command)
    except AgentGateError as exc:
        print(json.dumps({"error": exc.message, "context": exc.context}, ensure_ascii=False), file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, ensure_ascii=False), file=sys.stderr)
        return 2


def _compile(arguments: argparse.Namespace) -> int:
    pipeline = CompilationPipeline(store_path=arguments.store)
    result = pipeline.compile(arguments.bundle)
    written = AtomicOutputWriter(arguments.output).write({
        "return-list.json": result.return_list,
        "review-package.json": result.review_package,
        "remediation-plan.json": result.remediation_plan,
    })
    summary = {
        "bundle_id": result.bundle_id,
        "revision": result.revision,
        "decision": result.decision.value,
        "findings": len(result.findings),
        "outputs": [str(path) for path in written],
    }
    if arguments.summary:
        print(json.dumps(summary, ensure_ascii=False, sort_keys=True))
    else:
        print(f"{result.bundle_id} {result.revision}: {result.decision.value}; {len(result.findings)} findings")
        for path in written:
            print(path)
    return 0 if result.decision is Decision.ACCEPT else 1


def _history(arguments: argparse.Namespace) -> int:
    store = ReviewStore(arguments.store)
    history = store.history(arguments.bundle_id, arguments.fingerprint)
    print(json.dumps(history, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if history else 1


def _artifact(arguments: argparse.Namespace) -> int:
    store = ReviewStore(arguments.store)
    value = store.load_artifact(arguments.bundle_id, arguments.revision, arguments.name)
    if value is None:
        print(json.dumps({"error": "artifact not found"}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    return 0
