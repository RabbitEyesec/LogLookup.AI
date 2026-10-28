"""Durable store, migrations and v2 configuration."""

from __future__ import annotations

import pytest

from engine.config import ConfigError, config_from_dict
from engine.store import Database
from engine.store.migrations import LATEST_VERSION


async def test_migrations_are_idempotent_and_versioned(tmp_path):
    path = tmp_path / "s.sqlite3"
    db = await Database(path).open()
    assert await db.schema_version() == LATEST_VERSION
    await db.close()
    db = await Database(path).open()                       # re-open: no re-apply
    rows = await db.fetchall("SELECT version FROM schema_migrations")
    assert [r["version"] for r in rows] == [1, 2, 3]
    mode = await db.fetchone("PRAGMA journal_mode")
    assert list(mode.values())[0] == "wal"
    assert oct(path.stat().st_mode & 0o777) == "0o600"      # owner-only
    await db.close()


async def test_snapshot_is_a_consistent_usable_copy(tmp_path):
    db = await Database(tmp_path / "s.sqlite3").open()
    await db.execute("INSERT INTO source_errors (connection_id, code, detail, occurred_at)"
                     " VALUES ('c','x','d','now')")
    copy = await db.snapshot(tmp_path / "backup" / "copy.sqlite3")
    await db.close()
    other = await Database(copy).open()
    assert (await other.fetchone("SELECT COUNT(*) AS n FROM source_errors"))["n"] == 1
    await other.close()


def test_sources_parse_validate_and_reject_duplicates():
    cfg = config_from_dict({"sources": [
        {"id": "s1", "provider": "sentinel", "enabled": True, "poll_seconds": 90,
         "options": {"workspace_id": "w"}}]})
    assert cfg.sources[0].poll_seconds == 90 and cfg.sources[0].origin == "config"
    for bad in (
        [{"id": "a", "provider": "qradar"}],
        [{"id": "a", "provider": "elastic"}, {"id": "a", "provider": "elastic"}],
        [{"id": "has space", "provider": "elastic"}],
        [{"id": "a", "provider": "elastic", "poll_seconds": 1}],
    ):
        with pytest.raises(ConfigError):
            config_from_dict({"sources": bad})


def test_legacy_siem_block_surfaces_as_elastic_default():
    cfg = config_from_dict({"siem": {"host": "https://es.example.invalid:9200"}})
    legacy = cfg.effective_sources()
    assert [c.connection_id for c in legacy] == ["elastic-default"]
    assert legacy[0].origin == "legacy"
    assert config_from_dict({"siem": {"host": ""}}).effective_sources() == ()


def test_safety_switches_cannot_be_configured_off():
    for section in ({"outputs": {"logic_apps": {"require_explicit_approval": False}}},
                    {"outputs": {"logic_apps": {"unknown_delivery_policy": "retry"}}},
                    {"storage": {"evidence_encryption": False}}):
        with pytest.raises(ConfigError):
            config_from_dict(section)


def test_response_channel_and_new_providers_default_off():
    cfg = config_from_dict({})
    assert cfg.logic_apps.enabled is False and cfg.logic_apps.allowed_workflows == ()
    assert cfg.sources == () and cfg.scope_id == "org-local"


def test_example_config_loads():
    from engine.config import load_config
    cfg = load_config("config.example.yaml")
    assert {s.provider for s in cfg.sources} >= {"sentinel", "splunk", "defender_xdr", "entra_id"}
    assert all(not s.active for s in cfg.sources if s.provider != "elastic")


async def test_raw_retention_drops_payloads_but_keeps_hashes(tmp_path):
    from tests.v2_helpers import SENTINEL_SRC, MockVendors, build_runtime, settle
    rt = await build_runtime(tmp_path, [SENTINEL_SRC], MockVendors())
    try:
        await settle(rt, 1)
        await rt.db.execute("UPDATE source_events SET observed_at='2000-01-01T00:00:00.000Z'")
        await rt._purge_expired_evidence()
        row = await rt.db.fetchone("SELECT raw_enc, raw_sha256 FROM source_events")
        assert row["raw_enc"] is None and len(row["raw_sha256"]) == 64
        ev = await rt.ledger.get_event(
            (await rt.db.fetchone("SELECT canonical_event_id AS c FROM source_events"))["c"],
            include_raw=True)
        assert "raw" not in ev                      # expired payload is simply absent
    finally:
        await rt.stop()


async def test_data_directory_is_owner_only(tmp_path):
    db = await Database(tmp_path / "var" / "s.sqlite3").open()
    await db.close()
    assert oct((tmp_path / "var").stat().st_mode & 0o777) == "0o700"


async def test_legacy_connection_is_listed_only_when_it_is_polling(tmp_path):
    import json

    import httpx

    from engine.ai.service import TriageService
    from engine.config import config_from_dict
    from engine.pipeline import Pipeline
    from engine.runtime import V2Runtime
    from engine.secure.store import SecretStore

    cfg = config_from_dict({"siem": {"host": "https://es.example.invalid:9200"}})

    async def start(include):
        async def probe():
            return {"status": "healthy"}
        rt = V2Runtime(cfg, Pipeline(cfg), TriageService(cfg, ai_enabled=False),
                       SecretStore(tmp_path / f"h{include}"), tmp_path / f"h{include}",
                       include_legacy=include, legacy_health=probe,
                       http_transport=httpx.MockTransport(lambda r: httpx.Response(404)))
        await rt.start()
        return rt

    off = await start(False)
    on = await start(True)
    try:
        assert await off.repo.list() == []
        (conn, paused), = await on.repo.list()
        view = await on.connection_view(conn, paused)
        assert conn.connection_id == "elastic-default"
        assert view["managed_by"] == "legacy_poll" and view["health"]["status"] == "healthy"
    finally:
        await off.stop()
        await on.stop()
