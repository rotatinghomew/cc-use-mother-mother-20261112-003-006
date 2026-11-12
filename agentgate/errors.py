from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class AgentGateError(Exception):
    exit_code = 2

    def __init__(self, message: str, *, context: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.context = context or {}


class BundleReadError(AgentGateError):
    exit_code = 3


class SchemaDefinitionError(AgentGateError):
    exit_code = 4


class StorageError(AgentGateError):
    exit_code = 5


class CompilationAborted(AgentGateError):
    exit_code = 6


@dataclass(frozen=True)
class ParseProblem:
    document: str
    pointer: str
    message: str

    def as_dict(self) -> dict[str, str]:
        return {"document": self.document, "pointer": self.pointer, "message": self.message}
