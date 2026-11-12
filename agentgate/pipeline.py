from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .bundle import BundleReader, SubmissionCatalog
from .diff import BaselineDiffer
from .domain import CompilationResult, Finding, Severity, SourceLocation, ValidationContext
from .evidence import EvidenceCoverageTracker
from .matrices import CapabilityMatrixChecker
from .references import ReferenceResolver
from .remediation import RemediationPlanBuilder
from .review import DeclarationSignatureVerifier, FindingManager, ReviewPackageBuilder, ReturnListBuilder, ReviewStore, TraceabilityLedger
from .review.policies import RegulatoryPolicyChecker
from .schemas import SchemaRegistry
from .schemas.normalizer import DocumentNormalizer


class CompilationPipeline:
    def __init__(
        self,
        *,
        schema_registry: SchemaRegistry | None = None,
        trust_keys: Mapping[str, str] | None = None,
        store_path: str | Path | None = None,
    ) -> None:
        self.schemas = schema_registry or SchemaRegistry()
        self.normalizer = DocumentNormalizer()
        self.references = ReferenceResolver()
        self.catalog = SubmissionCatalog()
        self.matrix = CapabilityMatrixChecker()
        self.evidence = EvidenceCoverageTracker()
        self.differ = BaselineDiffer()
        self.signatures = DeclarationSignatureVerifier(trust_keys)
        self.policies = RegulatoryPolicyChecker()
        self.traceability = TraceabilityLedger()
        self.findings = FindingManager()
        self.return_lists = ReturnListBuilder()
        self.review_packages = ReviewPackageBuilder()
        self.remediation = RemediationPlanBuilder()
        self.store = ReviewStore(store_path) if store_path else None

    def compile(self, bundle_root: str | Path) -> CompilationResult:
        bundle = BundleReader(bundle_root).read()
        context = ValidationContext(bundle)
        context.metrics["compiler_schema"] = "agent-gate/v1"
        context.metrics["document_count"] = len(bundle.documents)
        self.schemas.validate_bundle(context)
        if not self._has_fatal_schema_problem(context):
            self.normalizer.normalize(context)
            self.catalog.build(context)
            self.references.resolve(context)
            self.matrix.check(context)
            self.evidence.track(context)
            self.differ.compare(context)
            self.signatures.verify(context)
            self.policies.check(context)
            self.traceability.build(context)
        self._integrity_rules(context)
        self.findings.finalize(context)
        if self.store is not None:
            self.store.synchronize(context)
            self.findings.finalize(context)
        return_list = self.return_lists.build(context)
        remediation_plan = self.remediation.build(context)
        review_package = self.review_packages.build(context)
        if self.store is not None:
            self.store.store_artifact(bundle.bundle_id, bundle.revision, "return-list", return_list)
            self.store.store_artifact(bundle.bundle_id, bundle.revision, "review-package", review_package)
            self.store.store_artifact(bundle.bundle_id, bundle.revision, "baseline-snapshot", self.differ.snapshot(context))
            self.store.store_artifact(bundle.bundle_id, bundle.revision, "remediation-plan", remediation_plan)
        return CompilationResult(
            bundle_id=bundle.bundle_id,
            revision=bundle.revision,
            decision=context.decision(),
            findings=tuple(context.findings),
            metrics=dict(context.metrics),
            return_list=return_list,
            review_package=review_package,
            remediation_plan=remediation_plan,
        )

    def _has_fatal_schema_problem(self, context: ValidationContext) -> bool:
        fatal_codes = {"SCHEMA_VERSION_UNSUPPORTED", "SCHEMA_DOCUMENT_MISSING"}
        return any(item.code in fatal_codes and item.severity is Severity.BLOCKER for item in context.findings)

    def _integrity_rules(self, context: ValidationContext) -> None:
        manifest_documents = context.bundle.raw_manifest.get("documents", [])
        expected = {}
        if isinstance(manifest_documents, list):
            for item in manifest_documents:
                if isinstance(item, Mapping) and isinstance(item.get("path"), str):
                    expected[item["path"]] = item.get("sha256")
        for document in context.bundle.all_documents():
            if document.name not in expected:
                context.add(Finding("INTEGRITY_DOCUMENT_UNLISTED", Severity.ERROR, "loaded document is not listed in the manifest", SourceLocation(document.name, "/")))
            digest = expected.get(document.name)
            if digest in (None, ""):
                context.add(Finding("INTEGRITY_DIGEST_NOT_DECLARED", Severity.WARNING, "manifest does not declare document digest", SourceLocation("manifest.json", "/documents"), subject=document.name))
        source_digest = hashlib.sha256()
        for document in context.bundle.all_documents():
            source_digest.update(document.kind.value.encode("utf-8"))
            source_digest.update(b"\0")
            source_digest.update(document.digest.encode("ascii"))
            source_digest.update(b"\0")
        context.metrics["bundle_content_digest"] = source_digest.hexdigest()


def compile_bundle(
    bundle_root: str | Path,
    *,
    store_path: str | Path | None = None,
    trust_keys: Mapping[str, str] | None = None,
) -> CompilationResult:
    return CompilationPipeline(store_path=store_path, trust_keys=trust_keys).compile(bundle_root)
