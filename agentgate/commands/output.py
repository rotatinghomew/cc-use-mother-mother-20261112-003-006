from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Mapping


class AtomicOutputWriter:
    def __init__(self, output: str | Path) -> None:
        self.output = Path(output).expanduser().resolve()

    def write(self, files: Mapping[str, Any]) -> list[Path]:
        self.output.mkdir(parents=True, exist_ok=True)
        written: list[Path] = []
        for name, value in files.items():
            target = self._safe_target(name)
            payload = json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
            self._atomic_write(target, payload)
            written.append(target)
        return written

    def _safe_target(self, name: str) -> Path:
        if not name or Path(name).name != name or not name.endswith(".json"):
            raise ValueError(f"invalid output file name: {name!r}")
        target = (self.output / name).resolve()
        target.relative_to(self.output)
        return target

    def _atomic_write(self, target: Path, payload: str) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=f".{target.name}.", suffix=".tmp", dir=target.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, target)
        except BaseException:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass
            raise
