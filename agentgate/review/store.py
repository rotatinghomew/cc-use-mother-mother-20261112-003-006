from __future__ import annotations

import json
import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Any, Iterable, Iterator, Mapping

from ..domain import ClosureAction, Finding, FindingState, Severity, SourceLocation, ValidationContext, utc_now
from ..errors import StorageError


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS bundles (
    bundle_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    submitted_at TEXT NOT NULL,
    compiled_at TEXT NOT NULL,
    decision TEXT NOT NULL,
    metrics_json TEXT NOT NULL,
    PRIMARY KEY(bundle_id, revision)
);
CREATE TABLE IF NOT EXISTS findings (
    bundle_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    code TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    document TEXT NOT NULL,
    pointer TEXT NOT NULL,
    subject TEXT NOT NULL,
    details_json TEXT NOT NULL,
    state TEXT NOT NULL,
    first_seen_revision TEXT NOT NULL,
    last_seen_revision TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY(bundle_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS finding_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    revision TEXT NOT NULL,
    event_type TEXT NOT NULL,
    state TEXT NOT NULL,
    operator TEXT NOT NULL,
    reason TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    recorded_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS finding_events_lookup ON finding_events(bundle_id, fingerprint, event_id);
CREATE TABLE IF NOT EXISTS artifacts (
    bundle_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    name TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY(bundle_id, revision, name)
);
"""


class ReviewStore:
    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).expanduser().resolve()

    def initialize(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            connection.executescript(SCHEMA)
            connection.commit()

    def synchronize(self, context: ValidationContext) -> None:
        self.initialize()
        with self.transaction() as connection:
            self._load_previous_states(connection, context)
            self._apply_bundle_closures(context)
            self._upsert_bundle(connection, context)
            active = set()
            for finding in context.findings:
                active.add(finding.fingerprint)
                self._upsert_finding(connection, context, finding)
                self._event_if_changed(connection, context, finding)
            self._resolve_disappeared(connection, context, active)

    def store_artifact(self, bundle_id: str, revision: str, name: str, payload: Mapping[str, Any] | list[Any]) -> None:
        self.initialize()
        encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True)
        with self.transaction() as connection:
            connection.execute(
                "INSERT INTO artifacts(bundle_id,revision,name,payload_json,created_at) VALUES(?,?,?,?,?) "
                "ON CONFLICT(bundle_id,revision,name) DO UPDATE SET payload_json=excluded.payload_json,created_at=excluded.created_at",
                (bundle_id, revision, name, encoded, utc_now()),
            )

    def load_artifact(self, bundle_id: str, revision: str, name: str) -> Any | None:
        self.initialize()
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT payload_json FROM artifacts WHERE bundle_id=? AND revision=? AND name=?", (bundle_id, revision, name)).fetchone()
        return json.loads(row[0]) if row else None

    def history(self, bundle_id: str, fingerprint: str) -> list[dict[str, Any]]:
        self.initialize()
        with closing(self._connect()) as connection:
            rows = connection.execute(
                "SELECT revision,event_type,state,operator,reason,evidence_json,recorded_at FROM finding_events "
                "WHERE bundle_id=? AND fingerprint=? ORDER BY event_id",
                (bundle_id, fingerprint),
            ).fetchall()
        return [
            {
                "revision": row["revision"],
                "event_type": row["event_type"],
                "state": row["state"],
                "operator": row["operator"],
                "reason": row["reason"],
                "evidence_ids": json.loads(row["evidence_json"]),
                "recorded_at": row["recorded_at"],
            }
            for row in rows
        ]

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            yield connection
            connection.commit()
        except sqlite3.Error as exc:
            connection.rollback()
            raise StorageError("review store transaction failed", context={"error": str(exc)}) from exc
        finally:
            connection.close()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=20)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA busy_timeout=20000")
        return connection

    def _load_previous_states(self, connection: sqlite3.Connection, context: ValidationContext) -> None:
        rows = connection.execute(
            "SELECT fingerprint,state,first_seen_revision,last_seen_revision FROM findings WHERE bundle_id=?",
            (context.bundle.bundle_id,),
        ).fetchall()
        previous = {row["fingerprint"]: row for row in rows}
        for finding in context.findings:
            row = previous.get(finding.fingerprint)
            if row is None:
                continue
            finding.state = FindingState(row["state"])
            finding.first_seen_revision = row["first_seen_revision"]
            finding.last_seen_revision = context.bundle.revision

    def _apply_bundle_closures(self, context: ValidationContext) -> None:
        document = context.bundle.get(__import__("agentgate.domain", fromlist=["DocumentKind"]).DocumentKind.CLOSURES)
        if document is None:
            return
        items = document.data.get("items", [])
        if not isinstance(items, list):
            return
        by_fingerprint = {finding.fingerprint: finding for finding in context.findings}
        evidence_ids = self._evidence_ids(context)
        for index, item in enumerate(items):
            if not isinstance(item, Mapping):
                continue
            fingerprint = str(item.get("finding_fingerprint", ""))
            finding = by_fingerprint.get(fingerprint)
            location = SourceLocation(document.name, f"/items/{index}")
            if finding is None:
                context.add(Finding("CLOSURE_FINDING_UNKNOWN", Severity.ERROR, "closure refers to an unknown active finding", location, subject=fingerprint))
                continue
            action = str(item.get("action", ""))
            requested_evidence = tuple(str(value) for value in item.get("evidence_ids", []) if value)
            missing = sorted(set(requested_evidence) - evidence_ids)
            if missing:
                context.add(Finding("CLOSURE_EVIDENCE_UNKNOWN", Severity.ERROR, "closure refers to unknown evidence", location, subject=fingerprint, details={"missing": missing}))
                continue
            if action in {"verify", "waive"} and not requested_evidence:
                context.add(Finding("CLOSURE_EVIDENCE_REQUIRED", Severity.ERROR, "verification and waiver actions require evidence", location, subject=fingerprint))
                continue
            transition = {
                "acknowledge": FindingState.ACKNOWLEDGED,
                "fix": FindingState.FIXED,
                "verify": FindingState.VERIFIED,
                "waive": FindingState.WAIVED,
            }.get(action)
            if transition is None:
                continue
            if not self._transition_allowed(finding.state, transition):
                context.add(Finding("CLOSURE_TRANSITION_INVALID", Severity.ERROR, "finding state transition is invalid", location, subject=fingerprint, details={"from": finding.state.value, "to": transition.value}))
                continue
            finding.state = transition

    def _transition_allowed(self, current: FindingState, target: FindingState) -> bool:
        allowed = {
            FindingState.OPEN: {FindingState.ACKNOWLEDGED, FindingState.FIXED, FindingState.WAIVED},
            FindingState.ACKNOWLEDGED: {FindingState.FIXED, FindingState.WAIVED},
            FindingState.FIXED: {FindingState.VERIFIED, FindingState.OPEN},
            FindingState.VERIFIED: {FindingState.OPEN},
            FindingState.WAIVED: {FindingState.OPEN},
        }
        return target in allowed[current]

    def _evidence_ids(self, context: ValidationContext) -> set[str]:
        from ..domain import DocumentKind
        document = context.bundle.get(DocumentKind.EVIDENCE)
        if document is None or not isinstance(document.data.get("items"), list):
            return set()
        return {str(item.get("id")) for item in document.data["items"] if isinstance(item, Mapping) and item.get("id")}

    def _upsert_bundle(self, connection: sqlite3.Connection, context: ValidationContext) -> None:
        connection.execute(
            "INSERT INTO bundles(bundle_id,revision,schema_version,submitted_at,compiled_at,decision,metrics_json) VALUES(?,?,?,?,?,?,?) "
            "ON CONFLICT(bundle_id,revision) DO UPDATE SET compiled_at=excluded.compiled_at,decision=excluded.decision,metrics_json=excluded.metrics_json",
            (
                context.bundle.bundle_id,
                context.bundle.revision,
                context.bundle.schema_version,
                context.bundle.submitted_at,
                utc_now(),
                context.decision().value,
                json.dumps(context.metrics, ensure_ascii=False, sort_keys=True),
            ),
        )

    def _upsert_finding(self, connection: sqlite3.Connection, context: ValidationContext, finding: Finding) -> None:
        connection.execute(
            "INSERT INTO findings(bundle_id,fingerprint,code,severity,message,document,pointer,subject,details_json,state,first_seen_revision,last_seen_revision,updated_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?) ON CONFLICT(bundle_id,fingerprint) DO UPDATE SET code=excluded.code,severity=excluded.severity,message=excluded.message," 
            "document=excluded.document,pointer=excluded.pointer,subject=excluded.subject,details_json=excluded.details_json,state=excluded.state,last_seen_revision=excluded.last_seen_revision,updated_at=excluded.updated_at",
            (
                context.bundle.bundle_id, finding.fingerprint, finding.code, finding.severity.value, finding.message,
                finding.location.document, finding.location.pointer, finding.subject,
                json.dumps(finding.details, ensure_ascii=False, sort_keys=True), finding.state.value,
                finding.first_seen_revision, finding.last_seen_revision, utc_now(),
            ),
        )

    def _event_if_changed(self, connection: sqlite3.Connection, context: ValidationContext, finding: Finding) -> None:
        row = connection.execute(
            "SELECT state FROM finding_events WHERE bundle_id=? AND fingerprint=? ORDER BY event_id DESC LIMIT 1",
            (context.bundle.bundle_id, finding.fingerprint),
        ).fetchone()
        if row is not None and row["state"] == finding.state.value:
            return
        event_type = "detected" if row is None else "state_changed"
        connection.execute(
            "INSERT INTO finding_events(bundle_id,fingerprint,revision,event_type,state,operator,reason,evidence_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (context.bundle.bundle_id, finding.fingerprint, context.bundle.revision, event_type, finding.state.value, "compiler", "synchronized from bundle compilation", "[]", utc_now()),
        )

    def _resolve_disappeared(self, connection: sqlite3.Connection, context: ValidationContext, active: set[str]) -> None:
        rows = connection.execute(
            "SELECT fingerprint,state FROM findings WHERE bundle_id=? AND last_seen_revision<>?",
            (context.bundle.bundle_id, context.bundle.revision),
        ).fetchall()
        for row in rows:
            if row["fingerprint"] in active or row["state"] in {FindingState.VERIFIED.value, FindingState.WAIVED.value}:
                continue
            connection.execute("UPDATE findings SET state=?,updated_at=? WHERE bundle_id=? AND fingerprint=?", (FindingState.FIXED.value, utc_now(), context.bundle.bundle_id, row["fingerprint"]))
            connection.execute(
                "INSERT INTO finding_events(bundle_id,fingerprint,revision,event_type,state,operator,reason,evidence_json,recorded_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (context.bundle.bundle_id, row["fingerprint"], context.bundle.revision, "not_reproduced", FindingState.FIXED.value, "compiler", "finding disappeared in the current revision", "[]", utc_now()),
            )
