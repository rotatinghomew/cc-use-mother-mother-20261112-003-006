from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

from ..domain import Document, DocumentKind, Finding, Reference, Severity, SourceLocation, ValidationContext


@dataclass(frozen=True)
class GraphNode:
    kind: str
    identifier: str
    document: str
    pointer: str
    value: Mapping[str, Any]

    @property
    def key(self) -> tuple[str, str]:
        return self.kind, self.identifier


@dataclass(frozen=True)
class GraphEdge:
    source: tuple[str, str]
    target: tuple[str, str]
    relation: str
    document: str
    pointer: str
    required: bool


class ReferenceGraph:
    def __init__(self) -> None:
        self.nodes: dict[tuple[str, str], GraphNode] = {}
        self.edges: list[GraphEdge] = []
        self.outgoing: dict[tuple[str, str], list[GraphEdge]] = defaultdict(list)
        self.incoming: dict[tuple[str, str], list[GraphEdge]] = defaultdict(list)

    def add_node(self, node: GraphNode) -> bool:
        if node.key in self.nodes:
            return False
        self.nodes[node.key] = node
        return True

    def add_edge(self, edge: GraphEdge) -> None:
        self.edges.append(edge)
        self.outgoing[edge.source].append(edge)
        self.incoming[edge.target].append(edge)

    def reachable(self, start: tuple[str, str]) -> set[tuple[str, str]]:
        visited: set[tuple[str, str]] = set()
        queue = deque([start])
        while queue:
            current = queue.popleft()
            if current in visited:
                continue
            visited.add(current)
            for edge in self.outgoing.get(current, []):
                if edge.target not in visited:
                    queue.append(edge.target)
        return visited

    def cycles(self) -> list[list[tuple[str, str]]]:
        color: dict[tuple[str, str], int] = {}
        stack: list[tuple[str, str]] = []
        positions: dict[tuple[str, str], int] = {}
        cycles: list[list[tuple[str, str]]] = []

        def visit(node: tuple[str, str]) -> None:
            color[node] = 1
            positions[node] = len(stack)
            stack.append(node)
            for edge in self.outgoing.get(node, []):
                target = edge.target
                if target not in self.nodes:
                    continue
                state = color.get(target, 0)
                if state == 0:
                    visit(target)
                elif state == 1:
                    cycles.append(stack[positions[target]:] + [target])
            stack.pop()
            positions.pop(node, None)
            color[node] = 2

        for node in sorted(self.nodes):
            if color.get(node, 0) == 0:
                visit(node)
        canonical: dict[tuple[tuple[str, str], ...], list[tuple[str, str]]] = {}
        for cycle in cycles:
            core = cycle[:-1]
            if not core:
                continue
            rotations = [tuple(core[index:] + core[:index]) for index in range(len(core))]
            key = min(rotations)
            canonical[key] = list(key) + [key[0]]
        return list(canonical.values())

    def export(self) -> dict[str, Any]:
        return {
            "nodes": [
                {"kind": node.kind, "id": node.identifier, "document": node.document, "pointer": node.pointer}
                for node in sorted(self.nodes.values(), key=lambda item: item.key)
            ],
            "edges": [
                {
                    "source": list(edge.source),
                    "target": list(edge.target),
                    "relation": edge.relation,
                    "document": edge.document,
                    "pointer": edge.pointer,
                    "required": edge.required,
                }
                for edge in self.edges
            ],
        }


class ReferenceResolver:
    kind_aliases = {
        "identity": DocumentKind.IDENTITIES.value,
        "agent": DocumentKind.IDENTITIES.value,
        "identities": DocumentKind.IDENTITIES.value,
        "description": DocumentKind.DESCRIPTIONS.value,
        "descriptions": DocumentKind.DESCRIPTIONS.value,
        "discovery": DocumentKind.DISCOVERY.value,
        "interaction": DocumentKind.INTERACTIONS.value,
        "interactions": DocumentKind.INTERACTIONS.value,
        "capability": DocumentKind.INTERACTIONS.value,
        "capabilities": DocumentKind.INTERACTIONS.value,
        "tool": DocumentKind.TOOLS.value,
        "tools": DocumentKind.TOOLS.value,
        "declaration": DocumentKind.DECLARATIONS.value,
        "declarations": DocumentKind.DECLARATIONS.value,
        "evidence": DocumentKind.EVIDENCE.value,
        "ota": DocumentKind.OTA_PLAN.value,
        "ota_plan": DocumentKind.OTA_PLAN.value,
        "baseline": DocumentKind.BASELINE.value,
        "closure": DocumentKind.CLOSURES.value,
        "closures": DocumentKind.CLOSURES.value,
    }

    def resolve(self, context: ValidationContext) -> ReferenceGraph:
        graph = ReferenceGraph()
        owners: dict[tuple[str, str], GraphNode] = {}
        for document in context.bundle.all_documents():
            self._index_document(document, graph, owners, context)
        for document in context.bundle.all_documents():
            self._resolve_document_references(document, graph, context)
        self._check_identity_coverage(graph, context)
        self._check_cycles(graph, context)
        self._check_orphans(graph, context)
        context.indexes["reference_nodes"] = {f"{key[0]}:{key[1]}": node for key, node in graph.nodes.items()}
        context.artifacts["reference_graph"] = graph.export()
        context.metrics["reference_nodes"] = len(graph.nodes)
        context.metrics["reference_edges"] = len(graph.edges)
        return graph

    def _index_document(
        self,
        document: Document,
        graph: ReferenceGraph,
        owners: dict[tuple[str, str], GraphNode],
        context: ValidationContext,
    ) -> None:
        items = document.data.get("items")
        if not isinstance(items, list):
            return
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                continue
            identifier = item.get("id")
            if not isinstance(identifier, str) or not identifier:
                continue
            node = GraphNode(document.kind.value, identifier, document.name, f"/items/{index}", item)
            if not graph.add_node(node):
                previous = owners[node.key]
                context.add(
                    Finding(
                        "REFERENCE_DUPLICATE_GLOBAL_ID",
                        Severity.ERROR,
                        "identifier is duplicated within the same document kind",
                        SourceLocation(document.name, f"/items/{index}/id"),
                        subject=identifier,
                        details={"previous_document": previous.document, "previous_pointer": previous.pointer},
                    )
                )
            else:
                owners[node.key] = node

    def _resolve_document_references(self, document: Document, graph: ReferenceGraph, context: ValidationContext) -> None:
        for reference in document.references:
            normalized_kind = self.kind_aliases.get(reference.target_kind, reference.target_kind)
            target = (normalized_kind, reference.target_id)
            source = self._owner_for_pointer(document, reference.source_pointer, graph)
            source_key = source.key if source else (document.kind.value, f"@document:{document.name}")
            if source is None and source_key not in graph.nodes:
                graph.add_node(GraphNode(source_key[0], source_key[1], document.name, "/", document.data))
            edge = GraphEdge(
                source=source_key,
                target=target,
                relation=reference.relation,
                document=reference.source_document,
                pointer=reference.source_pointer,
                required=reference.required,
            )
            graph.add_edge(edge)
            if target not in graph.nodes:
                severity = Severity.ERROR if reference.required else Severity.WARNING
                context.add(
                    Finding(
                        "REFERENCE_TARGET_MISSING",
                        severity,
                        f"reference target {normalized_kind}:{reference.target_id} does not exist",
                        SourceLocation(reference.source_document, reference.source_pointer),
                        subject=reference.target_id,
                        details={"target_kind": normalized_kind, "relation": reference.relation},
                    )
                )

    def _owner_for_pointer(self, document: Document, pointer: str, graph: ReferenceGraph) -> GraphNode | None:
        parts = pointer.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "items" and parts[1].isdigit():
            index = int(parts[1])
            items = document.data.get("items")
            if isinstance(items, list) and index < len(items) and isinstance(items[index], Mapping):
                identifier = items[index].get("id")
                if isinstance(identifier, str):
                    return graph.nodes.get((document.kind.value, identifier))
        return None

    def _check_identity_coverage(self, graph: ReferenceGraph, context: ValidationContext) -> None:
        identity_kind = DocumentKind.IDENTITIES.value
        dependent_kinds = {
            DocumentKind.DESCRIPTIONS.value,
            DocumentKind.DISCOVERY.value,
            DocumentKind.INTERACTIONS.value,
            DocumentKind.TOOLS.value,
            DocumentKind.OTA_PLAN.value,
        }
        identity_ids = {identifier for kind, identifier in graph.nodes if kind == identity_kind}
        referenced_by_kind: dict[str, set[str]] = defaultdict(set)
        for edge in graph.edges:
            if edge.target[0] == identity_kind:
                referenced_by_kind[edge.source[0]].add(edge.target[1])
        for kind in dependent_kinds:
            missing = identity_ids - referenced_by_kind.get(kind, set())
            for identifier in sorted(missing):
                context.add(
                    Finding(
                        "REFERENCE_IDENTITY_COVERAGE_GAP",
                        Severity.ERROR,
                        f"agent {identifier} has no {kind} record",
                        SourceLocation("manifest.json", "/documents"),
                        subject=identifier,
                        details={"missing_kind": kind},
                    )
                )

    def _check_cycles(self, graph: ReferenceGraph, context: ValidationContext) -> None:
        allowed = {"evidence_ids", "references", "declaration_ids", "tool_ids"}
        for cycle in graph.cycles():
            cycle_edges = self._edges_for_cycle(cycle, graph.edges)
            if cycle_edges and all(edge.relation in allowed for edge in cycle_edges):
                continue
            path = [f"{kind}:{identifier}" for kind, identifier in cycle]
            first = cycle_edges[0] if cycle_edges else None
            context.add(
                Finding(
                    "REFERENCE_CYCLE",
                    Severity.WARNING,
                    "cross-document reference cycle requires manual review",
                    SourceLocation(first.document if first else "manifest.json", first.pointer if first else "/documents"),
                    details={"cycle": path},
                )
            )

    def _edges_for_cycle(self, cycle: list[tuple[str, str]], edges: Iterable[GraphEdge]) -> list[GraphEdge]:
        pairs = set(zip(cycle, cycle[1:]))
        return [edge for edge in edges if (edge.source, edge.target) in pairs]

    def _check_orphans(self, graph: ReferenceGraph, context: ValidationContext) -> None:
        ignored = {DocumentKind.IDENTITIES.value, DocumentKind.BASELINE.value, DocumentKind.CLOSURES.value}
        for key, node in graph.nodes.items():
            if key[0] in ignored or key[1].startswith("@document:"):
                continue
            if not graph.incoming.get(key) and not graph.outgoing.get(key):
                context.add(
                    Finding(
                        "REFERENCE_ORPHAN_RECORD",
                        Severity.WARNING,
                        "record is isolated from the declaration graph",
                        SourceLocation(node.document, node.pointer),
                        subject=node.identifier,
                        details={"kind": node.kind},
                    )
                )
