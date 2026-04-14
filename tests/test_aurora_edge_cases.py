import asyncio
import json
import os
import sys

from typing import Any

import pytest

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.aurora import AgentMerger, AgentTranslation, SummonerAgent
from tooling.aurora.agentclass import (
    AURORA_KEYED_RECEIVE_TYPE,
    _resolve_aurora_extractor_spec,
    _resolve_callable_reference,
    _resolve_callable_reference_from_source,
)
from tooling.aurora.agentmerger import _read_required_mapping_field


CONTEXT_KEY_PREFIX = "ctx:"


def module_resolver_helper(payload):
    return payload["pid"]


def module_seq_helper(payload):
    return payload["seq"]


def module_context_key(payload):
    return CONTEXT_KEY_PREFIX + payload["pid"]


def _wait_for_registration(client):
    client.loop.run_until_complete(client._wait_for_registration())


def _close_clients(*clients):
    for client in clients:
        if client is not None:
            client.loop.close()


def test_aurora_dna_passthrough_matches_core_when_no_keyed_receivers():
    agent = SummonerAgent(name="aurora-core-only")

    try:
        @agent.receive("plain")
        async def receive_plain(payload: dict) -> Any:
            return payload

        _wait_for_registration(agent)

        assert json.loads(agent.dna()) == json.loads(agent.core_dna())
        assert json.loads(agent.dna()) == json.loads(agent.aurora_dna())

        with_context_default = json.loads(agent.dna(include_context=True))
        with_context_core = json.loads(agent.core_dna(include_context=True))
        with_context_aurora = json.loads(agent.aurora_dna(include_context=True))

        assert with_context_default == with_context_core == with_context_aurora
        assert with_context_default[0]["type"] == "__context__"
        assert with_context_default[1]["type"] == "receive"
    finally:
        _close_clients(agent)


def test_keyed_receive_with_flow_parses_route_and_exports_normalized_route_key():
    agent = SummonerAgent(name="aurora-flow")

    try:
        agent.flow().activate()

        @agent.keyed_receive(" alpha, beta ", key_by="pid")
        async def handle(payload: dict) -> Any:
            return payload["pid"]

        _wait_for_registration(agent)

        assert "alpha,beta" in agent.receiver_index
        assert "alpha,beta" in agent.receiver_parsed_routes
        assert agent.loop.run_until_complete(agent.receiver_index["alpha,beta"].fn({"pid": "A"})) == "A"

        aurora_entry = next(
            entry for entry in json.loads(agent.dna()) if entry["type"] == AURORA_KEYED_RECEIVE_TYPE
        )
        assert aurora_entry["route"] == "alpha, beta"
        assert aurora_entry["route_key"] == "alpha,beta"
    finally:
        _close_clients(agent)


def test_keyed_receive_with_flow_parse_failure_warns_and_uses_raw_route(capsys):
    agent = SummonerAgent(name="aurora-flow-fallback")

    try:
        agent.flow().activate()

        @agent.keyed_receive("alpha beta", key_by="pid")
        async def handle(payload: dict) -> Any:
            return payload["pid"]

        _wait_for_registration(agent)

        assert "alpha beta" in agent.receiver_index
        assert "alpha beta" not in agent.receiver_parsed_routes
        assert agent.loop.run_until_complete(agent.receiver_index["alpha beta"].fn({"pid": "A"})) == "A"
        assert "could not parse route" in capsys.readouterr().err

        aurora_entry = next(
            entry for entry in json.loads(agent.dna()) if entry["type"] == AURORA_KEYED_RECEIVE_TYPE
        )
        assert aurora_entry["route_key"] == "alphabeta"
    finally:
        _close_clients(agent)


def test_keyed_receive_duplicate_route_overwrites_previous_handler(capsys):
    agent = SummonerAgent(name="aurora-duplicate")

    try:
        @agent.keyed_receive("duplicate", key_by="pid")
        async def handle_first(payload: dict) -> Any:
            return "first"

        @agent.keyed_receive("duplicate", key_by="pid")
        async def handle_second(payload: dict) -> Any:
            return "second"

        _wait_for_registration(agent)

        receiver = agent.receiver_index["duplicate"]
        assert agent.loop.run_until_complete(receiver.fn({"pid": "A"})) == "second"
        assert "already exists. Overwriting." in capsys.readouterr().err
    finally:
        _close_clients(agent)


def test_keyed_receive_releases_same_key_waiters_after_handler_exception():
    agent = SummonerAgent(name="aurora-exception")

    try:
        first_started = asyncio.Event()
        release_first = asyncio.Event()

        @agent.keyed_receive("explode", key_by="pid")
        async def handle(payload: dict) -> Any:
            if payload["seq"] == 1:
                first_started.set()
                await release_first.wait()
                raise RuntimeError("boom")
            return payload["seq"]

        _wait_for_registration(agent)
        receiver = agent.receiver_index["explode"]

        async def scenario():
            first = asyncio.create_task(receiver.fn({"pid": "A", "seq": 1}))
            await asyncio.wait_for(first_started.wait(), timeout=0.2)

            second = asyncio.create_task(receiver.fn({"pid": "A", "seq": 2}))
            await asyncio.sleep(0.01)
            assert not second.done()

            release_first.set()

            with pytest.raises(RuntimeError):
                await first

            return await second

        assert agent.loop.run_until_complete(scenario()) == 2
    finally:
        _close_clients(agent)


def test_agent_merger_falls_back_to_live_extractors_when_serialized_metadata_is_invalid():
    source = SummonerAgent(name="aurora-live-fallback")
    merged = None

    try:
        @source.keyed_receive("overlay", key_by=module_resolver_helper, seq_by=module_seq_helper)
        async def handle(payload: dict) -> Any:
            return payload["seq"]

        _wait_for_registration(source)

        dna = source._dna_aurora_receivers[0]
        dna["key_by_name"] = "missing.module:missing_key"
        dna["key_by_source"] = None
        dna["seq_by_name"] = "missing.module:missing_seq"
        dna["seq_by_source"] = None

        merged = AgentMerger([source], name="aurora-live-fallback-merged", close_subclients=False)
        merged.initiate_all()
        _wait_for_registration(merged)

        receiver = merged.receiver_index["overlay"]
        assert merged.loop.run_until_complete(receiver.fn({"pid": "A", "seq": 1})) == 1
        assert merged.loop.run_until_complete(receiver.fn({"pid": "A", "seq": 1})) is None
    finally:
        _close_clients(source, merged)


def test_agent_merger_skips_malformed_imported_keyed_receiver_with_warning(capsys):
    source = SummonerAgent(name="aurora-malformed-source")
    merged = None

    try:
        @source.keyed_receive("valid", key_by="pid")
        async def handle(payload: dict) -> Any:
            return payload["pid"]

        _wait_for_registration(source)

        malformed = dict(source._dna_aurora_receivers[0])
        malformed.pop("route", None)
        source._dna_aurora_receivers.append(malformed)

        merged = AgentMerger([source], name="aurora-malformed-merged", close_subclients=False)
        merged.initiate_all()
        _wait_for_registration(merged)

        assert merged.loop.run_until_complete(merged.receiver_index["valid"].fn({"pid": "A"})) == "A"
        assert "Failed to replay keyed receiver" in capsys.readouterr().err
    finally:
        _close_clients(source, merged)


def test_agent_translation_rebuilds_extractor_source_with_context_globals():
    source = SummonerAgent(name="aurora-context-source")
    translated = None

    try:
        @source.keyed_receive("context", key_by=module_context_key)
        async def handle(payload: dict) -> Any:
            return payload["value"]

        _wait_for_registration(source)

        entries = json.loads(source.dna(include_context=True))
        assert entries[0]["globals"]["CONTEXT_KEY_PREFIX"] == CONTEXT_KEY_PREFIX

        aurora_entry = next(entry for entry in entries if entry.get("type") == AURORA_KEYED_RECEIVE_TYPE)
        aurora_entry["key_by_name"] = "missing.module:module_context_key"

        translated = AgentTranslation(entries, name="aurora-context-translated")
        translated.initiate_all()
        _wait_for_registration(translated)

        receiver = translated.receiver_index["context"]
        assert translated.loop.run_until_complete(receiver.fn({"pid": "A", "value": 3})) == 3
    finally:
        _close_clients(source, translated)


def test_callable_resolution_helpers_cover_fallbacks_and_errors():
    globals_dict = {"module_resolver_helper": module_resolver_helper}

    assert _resolve_callable_reference(globals_dict, None) is None
    assert _resolve_callable_reference(globals_dict, "module_resolver_helper") is module_resolver_helper
    assert (
        _resolve_callable_reference(globals_dict, "missing.module:module_resolver_helper")
        is module_resolver_helper
    )
    assert (
        _resolve_callable_reference(globals_dict, f"{__name__}:module_resolver_helper")
        is module_resolver_helper
    )
    assert _resolve_callable_reference(globals_dict, "missing.module:outer.<locals>.inner") is None

    rebuilt = _resolve_callable_reference_from_source(
        {},
        "rebuilt",
        "def rebuilt(payload):\n    return payload['pid']\n",
    )
    assert callable(rebuilt)
    assert rebuilt({"pid": "A"}) == "A"
    assert getattr(rebuilt, "__dna_source__", "").strip().startswith("def rebuilt")

    assert _resolve_callable_reference_from_source({}, "missing", "def rebuilt(payload):\n    return payload['pid']\n") is None
    assert _resolve_callable_reference_from_source({}, "mod:<lambda>", "value = 1\n") is None


def test_aurora_internal_resolvers_raise_for_invalid_specs():
    assert _resolve_aurora_extractor_spec({}, "none", None, None, None, label="key_by") is None
    assert _resolve_aurora_extractor_spec({}, "field", "pid", None, None, label="key_by") == "pid"

    with pytest.raises(ValueError):
        _resolve_aurora_extractor_spec({}, "field", "", None, None, label="key_by")

    with pytest.raises(ValueError):
        _resolve_aurora_extractor_spec(
            {},
            "callable",
            None,
            "missing.module:missing_key",
            None,
            label="key_by",
        )

    with pytest.raises(ValueError):
        _resolve_aurora_extractor_spec({}, "unknown", None, None, None, label="key_by")

    with pytest.raises(KeyError):
        _read_required_mapping_field({}, "route")
