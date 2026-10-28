"""Elastic results sink: the existing idempotent ``cluster_id`` write-back."""

from __future__ import annotations

from engine.connectors.writeback import ResultWriter


class ElasticResultsSink(ResultWriter):
    name = "elastic_results"
