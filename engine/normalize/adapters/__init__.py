"""Source adapters: translate one source's fields into the OCSF interface."""

from engine.normalize.adapters.base import (
    AdapterInterface,
    AdapterNotImplemented,
    get_adapter,
)

__all__ = ["AdapterInterface", "AdapterNotImplemented", "get_adapter"]
