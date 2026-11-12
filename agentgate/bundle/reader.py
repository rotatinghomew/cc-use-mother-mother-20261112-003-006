from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ..domain import Bundle, Document, DocumentKind, Reference
from ..errors import BundleReadError


class BundleReader:
    maximum_document_bytes = 2_000_000
    allowed_suffixes = {".json"}

    def __init__(self, root: str | Path) -> None:
        self.root = Path(root).expanduser().resolve()

    def read(self) -> Bundle:
        self._guard_root()
        manifest_path = self.root / "manifest.json"
        manifest = self._load_json(manifest_path)
        self._validate_manifest_shape(manifest)
        documents: dict[DocumentKind, Document] = {}
        for entry in manifest["documents"]:
            kind = self._parse_kind(entry.get("kind"))
            if kind is DocumentKind.MANIFEST:
                raise BundleReadError("manifest cannot declare itself as a content document")
            if kind in documents:
                raise BundleReadError("duplicate document kind", context={"kind": kind.value})
            path = self._resolve_document_path(entry.get("path"))
            data = self._load_json(path)
            version = str(entry.get("version") or data.get("schema_version") or manifest["schema_version"])
            digest = self._digest(path)
            expected_digest = entry.get("sha256")
            if expected_digest and expected_digest != digest:
                raise BundleReadError(
                    "document digest does not match manifest",
                    context={"path": path.name, "expected": expected_digest, "actual": digest},
                )
            document = Document(
                name=path.name,
                kind=kind,
                version=version,
                data=data,
                digest=digest,
                path=path,
                references=self._extract_references(path.name, data),
            )
            documents[kind] = document
        return Bundle(
            root=self.root,
            bundle_id=str(manifest["bundle_id"]),
            revision=str(manifest["revision"]),
            schema_version=str(manifest["schema_version"]),
            submitted_at=str(manifest["submitted_at"]),
            documents=documents,
            raw_manifest=manifest,
        )

    def _guard_root(self) -> None:
        if not self.root.is_dir():
            raise BundleReadError("bundle root does not exist", context={"root": str(self.root)})
        if self.root.is_symlink():
            raise BundleReadError("bundle root must not be a symbolic link")

    def _load_json(self, path: Path) -> dict[str, Any]:
        if not path.is_file():
            raise BundleReadError("required JSON document is missing", context={"path": str(path)})
        if path.is_symlink():
            raise BundleReadError("symbolic links are not accepted", context={"path": str(path)})
        if path.suffix.lower() not in self.allowed_suffixes:
            raise BundleReadError("unsupported document format", context={"path": str(path)})
        size = path.stat().st_size
        if size > self.maximum_document_bytes:
            raise BundleReadError("document exceeds size limit", context={"path": str(path), "bytes": size})
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except UnicodeError as exc:
            raise BundleReadError("document is not valid UTF-8", context={"path": str(path)}) from exc
        except json.JSONDecodeError as exc:
            raise BundleReadError(
                "document is not valid JSON",
                context={"path": str(path), "line": exc.lineno, "column": exc.colno},
            ) from exc
        if not isinstance(value, dict):
            raise BundleReadError("document root must be an object", context={"path": str(path)})
        return value

    def _resolve_document_path(self, value: object) -> Path:
        if not isinstance(value, str) or not value.strip():
            raise BundleReadError("document path must be a non-empty string")
        candidate = (self.root / value).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError as exc:
            raise BundleReadError("document path escapes bundle root", context={"path": value}) from exc
        return candidate

    def _parse_kind(self, value: object) -> DocumentKind:
        if not isinstance(value, str):
            raise BundleReadError("document kind must be a string")
        try:
            return DocumentKind(value)
        except ValueError as exc:
            raise BundleReadError("unknown document kind", context={"kind": value}) from exc

    def _validate_manifest_shape(self, manifest: Mapping[str, Any]) -> None:
        for field in ("bundle_id", "revision", "schema_version", "submitted_at"):
            if not isinstance(manifest.get(field), str) or not manifest[field].strip():
                raise BundleReadError("manifest field is missing", context={"field": field})
        documents = manifest.get("documents")
        if not isinstance(documents, list) or not documents:
            raise BundleReadError("manifest documents must be a non-empty array")
        for index, item in enumerate(documents):
            if not isinstance(item, Mapping):
                raise BundleReadError("manifest document entry must be an object", context={"index": index})
            for field in ("kind", "path"):
                if not isinstance(item.get(field), str) or not item[field].strip():
                    raise BundleReadError("manifest document field is missing", context={"index": index, "field": field})

    def _digest(self, path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(64 * 1024):
                digest.update(chunk)
        return digest.hexdigest()

    def _extract_references(self, document: str, data: Mapping[str, Any]) -> list[Reference]:
        references: list[Reference] = []
        explicit = data.get("references", [])
        if isinstance(explicit, list):
            for index, item in enumerate(explicit):
                if not isinstance(item, Mapping):
                    continue
                target_kind = item.get("kind")
                target_id = item.get("id")
                if isinstance(target_kind, str) and isinstance(target_id, str):
                    references.append(
                        Reference(
                            source_document=document,
                            source_pointer=f"/references/{index}",
                            target_kind=target_kind,
                            target_id=target_id,
                            relation=str(item.get("relation", "references")),
                            required=bool(item.get("required", True)),
                        )
                    )
        self._walk_implicit_references(document, data, "", references)
        unique: dict[tuple[str, str, str, str], Reference] = {}
        for reference in references:
            key = (reference.source_pointer, reference.target_kind, reference.target_id, reference.relation)
            unique[key] = reference
        return list(unique.values())

    def _walk_implicit_references(
        self,
        document: str,
        value: Any,
        pointer: str,
        output: list[Reference],
    ) -> None:
        singular = {
            "agent_id": "identities",
            "capability_id": "capability",
            "tool_id": "tools",
            "declaration_id": "declarations",
            "evidence_id": "evidence",
            "baseline_id": "baseline",
        }
        plural = {
            "agent_ids": "identities",
            "capability_ids": "capability",
            "tool_ids": "tools",
            "declaration_ids": "declarations",
            "evidence_ids": "evidence",
        }
        if isinstance(value, Mapping):
            for key, item in value.items():
                child = f"{pointer}/{self._escape(str(key))}"
                if key in singular and isinstance(item, str) and item:
                    output.append(Reference(document, child, singular[key], item, key, True))
                elif key in plural and isinstance(item, list):
                    for index, identifier in enumerate(item):
                        if isinstance(identifier, str) and identifier:
                            output.append(Reference(document, f"{child}/{index}", plural[key], identifier, key, True))
                self._walk_implicit_references(document, item, child, output)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                self._walk_implicit_references(document, item, f"{pointer}/{index}", output)

    def _escape(self, value: str) -> str:
        return value.replace("~", "~0").replace("/", "~1")
