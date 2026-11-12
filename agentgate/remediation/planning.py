from __future__ import annotations

import hashlib
import json
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from ..domain import Finding, FindingState, Severity, ValidationContext, utc_now


@dataclass(frozen=True)
class RemediationRule:
    prefix: str
    owner: str
    action: str
    evidence: tuple[str, ...]
    blocks: tuple[str, ...] = ()
    closure: str = "recompile the bundle and verify the finding no longer reproduces"


@dataclass
class RemediationTask:
    task_id: str
    title: str
    owner: str
    priority: int
    finding_fingerprints: list[str]
    finding_codes: list[str]
    documents: list[str]
    pointers: list[str]
    subjects: list[str]
    required_actions: list[str]
    required_evidence: list[str]
    closure_criteria: list[str]
    depends_on: list[str] = field(default_factory=list)
    wave: int = 0
    risk_score: int = 0

    def as_dict(self) -> dict[str, Any]:
        return {
            "task_id": self.task_id,
            "title": self.title,
            "owner": self.owner,
            "priority": self.priority,
            "risk_score": self.risk_score,
            "wave": self.wave,
            "depends_on": list(self.depends_on),
            "finding_fingerprints": list(self.finding_fingerprints),
            "finding_codes": list(self.finding_codes),
            "documents": list(self.documents),
            "pointers": list(self.pointers),
            "subjects": list(self.subjects),
            "required_actions": list(self.required_actions),
            "required_evidence": list(self.required_evidence),
            "closure_criteria": list(self.closure_criteria),
        }


class RemediationPlanBuilder:
    severity_weight = {
        Severity.BLOCKER: 100,
        Severity.ERROR: 60,
        Severity.WARNING: 25,
        Severity.INFO: 5,
    }
    rules = (
        RemediationRule(
            "SCHEMA",
            "submission-contract",
            "repair document structure, required fields, identifiers, and schema versions",
            ("schema validation report", "normalized document excerpt"),
            ("REFERENCE", "MATRIX", "EVIDENCE", "POLICY", "TRACE", "DIFF"),
            "all affected documents validate against the declared schema without blocker or error findings",
        ),
        RemediationRule(
            "CATALOG",
            "submission-contract",
            "restore unique identifiers and a complete per-agent document inventory",
            ("catalog inventory", "identifier collision check"),
            ("REFERENCE", "MATRIX", "EVIDENCE", "TRACE"),
        ),
        RemediationRule(
            "REFERENCE",
            "submission-integrator",
            "repair cross-document references, ownership, and graph reachability",
            ("reference graph export", "orphan and cycle report"),
            ("MATRIX", "EVIDENCE", "TRACE"),
        ),
        RemediationRule(
            "MATRIX",
            "capability-governance",
            "align interaction permissions, confirmation controls, audit records, tools, and declarations",
            ("capability matrix", "privileged-operation test evidence"),
            ("EVIDENCE", "POLICY", "TRACE"),
        ),
        RemediationRule(
            "EVIDENCE",
            "verification-lab",
            "supply fresh, passing, directly bound evidence for every declared control",
            ("test artifact digest", "execution timestamp", "subject binding"),
            ("CLOSURE",),
        ),
        RemediationRule(
            "SIGNATURE",
            "application-declarations",
            "regenerate the declaration payload digest and signature with the configured trust key",
            ("canonical payload", "signature verification result"),
            ("MATRIX", "POLICY"),
        ),
        RemediationRule(
            "OTA",
            "release-assurance",
            "complete the online-upgrade scheme, impact assessment, rollback boundary, and completion evidence",
            ("upgrade scheme", "impact assessment", "completion report evidence"),
            ("DIFF", "EVIDENCE", "POLICY"),
        ),
        RemediationRule(
            "DIFF",
            "change-control",
            "reconcile the current declaration against the approved baseline and explain material changes",
            ("baseline comparison", "change approval record"),
            ("CLOSURE",),
        ),
        RemediationRule(
            "POLICY",
            "regulatory-review",
            "correct the regulatory rule violation and document the resulting operational boundary",
            ("policy check result", "reviewer rationale"),
            ("CLOSURE",),
        ),
        RemediationRule(
            "TRACE",
            "audit-traceability",
            "restore end-to-end links from identity and capability through evidence and destination",
            ("traceability ledger", "destination verification"),
            ("CLOSURE",),
        ),
        RemediationRule(
            "INTEGRITY",
            "submission-integrator",
            "declare and verify the digest of every submitted document",
            ("manifest digest inventory", "bundle content digest"),
            ("CLOSURE",),
        ),
        RemediationRule(
            "CLOSURE",
            "review-operations",
            "repair the finding lifecycle action and attach valid verification evidence",
            ("finding history", "closure evidence"),
        ),
    )

    def __init__(self) -> None:
        self.by_prefix = {rule.prefix: rule for rule in self.rules}

    def build(self, context: ValidationContext) -> dict[str, Any]:
        actionable = [finding for finding in context.findings if self._actionable(finding)]
        grouped = self._group_findings(actionable)
        tasks = [self._task(key, findings) for key, findings in sorted(grouped.items())]
        self._connect_dependencies(tasks)
        ordered, cycles = self._schedule(tasks)
        self._record_metrics(context, ordered, cycles)
        plan = {
            "format": "agent-gate-remediation-plan/v1",
            "bundle_id": context.bundle.bundle_id,
            "revision": context.bundle.revision,
            "generated_at": utc_now(),
            "decision": context.decision().value,
            "summary": self._summary(ordered, cycles),
            "tasks": [task.as_dict() for task in ordered],
            "dependency_cycles": cycles,
            "execution_analysis": self._execution_analysis(ordered, cycles),
            "integrity": self._integrity(ordered),
        }
        context.artifacts["remediation_plan"] = plan
        return plan

    def _actionable(self, finding: Finding) -> bool:
        return finding.state not in {FindingState.VERIFIED, FindingState.WAIVED} and finding.severity is not Severity.INFO

    def _group_findings(self, findings: Iterable[Finding]) -> dict[tuple[str, str, str], list[Finding]]:
        grouped: dict[tuple[str, str, str], list[Finding]] = defaultdict(list)
        for finding in findings:
            prefix = self._prefix(finding.code)
            subject = finding.subject or self._subject_from_details(finding.details) or finding.location.document
            grouped[(prefix, finding.location.document, subject)].append(finding)
        return grouped

    def _subject_from_details(self, details: Mapping[str, Any]) -> str:
        for key in ("target", "agent_id", "capability_id", "tool_id", "evidence_id"):
            value = details.get(key)
            if isinstance(value, str) and value:
                return value
        missing = details.get("missing")
        if isinstance(missing, list) and missing:
            return str(missing[0])
        return ""

    def _task(self, key: tuple[str, str, str], findings: list[Finding]) -> RemediationTask:
        prefix, document, subject = key
        rule = self.by_prefix.get(prefix, self._fallback_rule(prefix))
        codes = sorted({finding.code for finding in findings})
        fingerprints = sorted({finding.fingerprint for finding in findings if finding.fingerprint})
        pointers = sorted({finding.location.pointer for finding in findings})
        documents = sorted({finding.location.document for finding in findings})
        subjects = sorted({finding.subject for finding in findings if finding.subject})
        actions = self._actions(rule, findings)
        evidence = self._evidence(rule, findings)
        closure = self._closure(rule, findings)
        risk = self._risk(findings)
        identity = json.dumps([prefix, document, subject, codes], ensure_ascii=False, sort_keys=True)
        task_id = "REM-" + hashlib.sha256(identity.encode("utf-8")).hexdigest()[:12].upper()
        title_subject = subject if subject else document
        title = f"{prefix}: {title_subject}"
        return RemediationTask(
            task_id=task_id,
            title=title,
            owner=rule.owner,
            priority=self._priority(risk),
            risk_score=risk,
            finding_fingerprints=fingerprints,
            finding_codes=codes,
            documents=documents,
            pointers=pointers,
            subjects=subjects,
            required_actions=actions,
            required_evidence=evidence,
            closure_criteria=closure,
        )

    def _fallback_rule(self, prefix: str) -> RemediationRule:
        return RemediationRule(
            prefix,
            "submission-integrator",
            "inspect the finding details, correct the declared material, and recompile",
            ("corrected document", "recompilation result"),
        )

    def _actions(self, rule: RemediationRule, findings: list[Finding]) -> list[str]:
        values = [rule.action]
        for finding in findings:
            if finding.message:
                values.append(f"resolve {finding.code}: {finding.message}")
            missing = finding.details.get("missing")
            if isinstance(missing, list) and missing:
                values.append("provide missing identifiers: " + ", ".join(sorted(str(value) for value in missing)))
            expected = finding.details.get("expected")
            actual = finding.details.get("actual")
            if expected is not None and actual is not None:
                values.append(f"reconcile expected {expected!r} with actual {actual!r}")
        return self._unique(values)

    def _evidence(self, rule: RemediationRule, findings: list[Finding]) -> list[str]:
        values = list(rule.evidence)
        if any(finding.severity is Severity.BLOCKER for finding in findings):
            values.append("independent reviewer sign-off")
        if any(finding.code.startswith(("MATRIX", "POLICY", "SIGNATURE")) for finding in findings):
            values.append("negative-path regression test")
        if any(finding.code.startswith(("REFERENCE", "TRACE", "DIFF")) for finding in findings):
            values.append("machine-readable comparison artifact")
        return self._unique(values)

    def _closure(self, rule: RemediationRule, findings: list[Finding]) -> list[str]:
        values = [rule.closure]
        for finding in findings:
            values.append(f"finding {finding.code} at {finding.location.document}{finding.location.pointer} is absent or verified")
        values.append("no new blocker or error finding is introduced for the same subject")
        return self._unique(values)

    def _risk(self, findings: list[Finding]) -> int:
        score = 0
        for finding in findings:
            score += self.severity_weight[finding.severity]
            if finding.code.startswith(("SIGNATURE", "MATRIX_PRIVILEGED", "POLICY_TOOL")):
                score += 20
            if finding.code.startswith(("OTA", "DIFF")):
                score += 15
            if finding.location.pointer in ("/", "/items"):
                score += 5
        return score

    def _priority(self, risk: int) -> int:
        if risk >= 100:
            return 1
        if risk >= 70:
            return 2
        if risk >= 35:
            return 3
        return 4

    def _connect_dependencies(self, tasks: list[RemediationTask]) -> None:
        by_prefix: dict[str, list[RemediationTask]] = defaultdict(list)
        for task in tasks:
            by_prefix[task.finding_codes[0].split("_", 1)[0]].append(task)
        for task in tasks:
            prefix = task.finding_codes[0].split("_", 1)[0]
            rule = self.by_prefix.get(prefix, self._fallback_rule(prefix))
            dependencies: set[str] = set()
            for candidate_prefix, candidates in by_prefix.items():
                candidate_rule = self.by_prefix.get(candidate_prefix, self._fallback_rule(candidate_prefix))
                if prefix in candidate_rule.blocks:
                    for candidate in candidates:
                        if candidate.task_id != task.task_id and self._related(candidate, task):
                            dependencies.add(candidate.task_id)
            if prefix == "CLOSURE":
                dependencies.update(candidate.task_id for candidate in tasks if candidate.task_id != task.task_id)
            task.depends_on = sorted(dependencies)

    def _related(self, first: RemediationTask, second: RemediationTask) -> bool:
        if set(first.documents) & set(second.documents):
            return True
        if set(first.subjects) & set(second.subjects):
            return True
        return not first.subjects or not second.subjects

    def _schedule(self, tasks: list[RemediationTask]) -> tuple[list[RemediationTask], list[list[str]]]:
        by_id = {task.task_id: task for task in tasks}
        incoming = {task.task_id: {value for value in task.depends_on if value in by_id} for task in tasks}
        outgoing: dict[str, set[str]] = defaultdict(set)
        for task_id, dependencies in incoming.items():
            for dependency in dependencies:
                outgoing[dependency].add(task_id)
        ready = deque(sorted((task_id for task_id, values in incoming.items() if not values), key=lambda value: self._sort_key(by_id[value])))
        ordered: list[RemediationTask] = []
        while ready:
            task_id = ready.popleft()
            task = by_id[task_id]
            task.wave = 1 + max((by_id[value].wave for value in task.depends_on if value in by_id), default=0)
            ordered.append(task)
            for dependent in sorted(outgoing.get(task_id, ()), key=lambda value: self._sort_key(by_id[value])):
                incoming[dependent].discard(task_id)
                if not incoming[dependent]:
                    ready.append(dependent)
            ready = deque(sorted(ready, key=lambda value: self._sort_key(by_id[value])))
        remaining = sorted((task_id for task_id in by_id if task_id not in {task.task_id for task in ordered}))
        cycles: list[list[str]] = []
        if remaining:
            cycles = self._components(remaining, incoming)
            for task_id in remaining:
                task = by_id[task_id]
                task.wave = max((item.wave for item in ordered), default=0) + 1
                ordered.append(task)
        return sorted(ordered, key=self._sort_key), cycles

    def _components(self, remaining: list[str], incoming: Mapping[str, set[str]]) -> list[list[str]]:
        pool = set(remaining)
        result: list[list[str]] = []
        while pool:
            seed = min(pool)
            component = {seed}
            frontier = [seed]
            while frontier:
                current = frontier.pop()
                neighbors = set(incoming.get(current, set())) & pool
                neighbors.update(task_id for task_id in pool if current in incoming.get(task_id, set()))
                for neighbor in neighbors - component:
                    component.add(neighbor)
                    frontier.append(neighbor)
            pool -= component
            result.append(sorted(component))
        return result

    def _sort_key(self, task: RemediationTask) -> tuple[int, int, str]:
        return task.wave, task.priority, task.task_id

    def _summary(self, tasks: list[RemediationTask], cycles: list[list[str]]) -> dict[str, Any]:
        return {
            "task_count": len(tasks),
            "wave_count": max((task.wave for task in tasks), default=0),
            "dependency_cycle_count": len(cycles),
            "priority_counts": dict(sorted(Counter(str(task.priority) for task in tasks).items())),
            "owner_counts": dict(sorted(Counter(task.owner for task in tasks).items())),
            "finding_count": sum(len(task.finding_fingerprints) for task in tasks),
        }

    def _execution_analysis(self, tasks: list[RemediationTask], cycles: list[list[str]]) -> dict[str, Any]:
        by_id = {task.task_id: task for task in tasks}
        waves: dict[int, list[str]] = defaultdict(list)
        owners: dict[str, dict[str, Any]] = {}
        for task in tasks:
            waves[task.wave].append(task.task_id)
            workload = owners.setdefault(task.owner, {"task_ids": [], "risk_score": 0, "priority_one": 0})
            workload["task_ids"].append(task.task_id)
            workload["risk_score"] += task.risk_score
            workload["priority_one"] += int(task.priority == 1)
        for workload in owners.values():
            workload["task_ids"].sort()
            workload["task_count"] = len(workload["task_ids"])
        critical = self._critical_path(tasks)
        ready = sorted(task.task_id for task in tasks if not task.depends_on)
        blocked = sorted(task.task_id for task in tasks if task.depends_on)
        closure_ready = not cycles and all(task.wave > 0 for task in tasks)
        maximum_parallelism = max((len(task_ids) for task_ids in waves.values()), default=0)
        bottleneck_owners = sorted(
            owner for owner, workload in owners.items()
            if workload["risk_score"] == max((item["risk_score"] for item in owners.values()), default=0)
        )
        return {
            "ready_task_ids": ready,
            "blocked_task_ids": blocked,
            "parallel_waves": [
                {"wave": wave, "task_ids": sorted(task_ids), "owners": sorted({by_id[task_id].owner for task_id in task_ids})}
                for wave, task_ids in sorted(waves.items())
            ],
            "owner_workload": dict(sorted(owners.items())),
            "critical_path_task_ids": critical,
            "critical_path_risk_score": sum(by_id[task_id].risk_score for task_id in critical),
            "maximum_parallelism": maximum_parallelism,
            "bottleneck_owners": bottleneck_owners,
            "serial_task_count": sum(len(task_ids) == 1 for task_ids in waves.values()),
            "all_tasks_scheduled": len(ready) + len(blocked) == len(tasks),
            "closure_ready": closure_ready,
            "manual_coordination_required": bool(cycles),
        }

    def _critical_path(self, tasks: list[RemediationTask]) -> list[str]:
        by_id = {task.task_id: task for task in tasks}
        paths: dict[str, tuple[int, tuple[str, ...]]] = {}
        for task in sorted(tasks, key=self._sort_key):
            candidates = [paths[dependency] for dependency in task.depends_on if dependency in paths]
            if candidates:
                previous_score, previous_path = max(candidates, key=lambda item: (item[0], item[1]))
            else:
                previous_score, previous_path = 0, ()
            paths[task.task_id] = previous_score + task.risk_score, previous_path + (task.task_id,)
        if not paths:
            return []
        return list(max(paths.values(), key=lambda item: (item[0], item[1]))[1])

    def _record_metrics(self, context: ValidationContext, tasks: list[RemediationTask], cycles: list[list[str]]) -> None:
        context.metrics["remediation_tasks"] = len(tasks)
        context.metrics["remediation_waves"] = max((task.wave for task in tasks), default=0)
        context.metrics["remediation_dependency_cycles"] = len(cycles)
        context.metrics["remediation_priority_one"] = sum(task.priority == 1 for task in tasks)

    def _integrity(self, tasks: list[RemediationTask]) -> dict[str, str]:
        payload = [task.as_dict() for task in tasks]
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return {"algorithm": "sha256", "digest": hashlib.sha256(encoded).hexdigest()}

    def _prefix(self, code: str) -> str:
        return code.split("_", 1)[0] if code else "GENERAL"

    def _unique(self, values: Iterable[str]) -> list[str]:
        output: list[str] = []
        seen: set[str] = set()
        for value in values:
            normalized = value.strip()
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            output.append(normalized)
        return output
