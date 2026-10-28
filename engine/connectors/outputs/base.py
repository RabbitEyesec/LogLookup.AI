"""Output sink contract."""

from __future__ import annotations

from typing import Any, Protocol


class OutputSink(Protocol):
    name: str

    async def write(self, doc: dict[str, Any]) -> bool: ...
