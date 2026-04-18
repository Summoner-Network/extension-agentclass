import asyncio
import json
import os
import sys

from typing import Any

import pytest

from summoner.protocol import Action
from summoner.protocol.process import Direction

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.aurora import AgentMerger, AgentTranslation, SummonerAgent
from tooling.aurora.utils.async_keyed_mutex import AsyncKeyedMutex


AURORA_CONTEXT = "aurora-context"
_BOUND_AGENT_NAME = "aurora_bound_agent"
_MISSING = object()
aurora_bound_agent: Any = None


def callable_pid(payload):
    return payload["pid"]


def callable_seq(payload):
    return payload["seq"]


def _bind_agent(agent):
    previous = globals().get(_BOUND_AGENT_NAME, _MISSING)
    globals()[_BOUND_AGENT_NAME] = agent
    return previous


def _restore_agent(previous):
    if previous is _MISSING:
        globals().pop(_BOUND_AGENT_NAME, None)
        return
    globals()[_BOUND_AGENT_NAME] = previous


def _wait_for_registration(client):
    client.loop.run_until_complete(client._wait_for_registration())


def _close_clients(*clients):
    for client in clients:
        if client is not None:
            client.loop.close()


def _register_mixed_handlers(agent, *, callable_extractors=False):
    directions_key = callable_pid if callable_extractors else "pid"
    overlay_key = callable_pid if callable_extractors else "pid"
    overlay_seq = callable_seq if callable_extractors else "seq"

    @agent.upload_states()
    async def upload_states(payload: dict) -> Any:
        return {
            "agent": aurora_bound_agent.name,
            "context": AURORA_CONTEXT,
            "payload": payload,
        }

    @agent.download_states()
    async def download_states(payload: dict) -> Any:
        return {
            "agent": aurora_bound_agent.name,
            "context": AURORA_CONTEXT,
            "payload": payload,
        }

    @agent.hook(Direction.RECEIVE, priority=(1,))
    async def rx_normalize(payload: dict) -> Any:
        if isinstance(payload, dict) and isinstance(payload.get("content"), dict):
            return payload["content"]
        return payload

    @agent.receive("audit", priority=(2,))
    async def receive_audit(payload: dict) -> Any:
        return {
            "agent": aurora_bound_agent.name,
            "context": AURORA_CONTEXT,
            "payload": payload,
        }

    @agent.keyed_receive("directions", key_by=directions_key, priority=(3,))
    async def receive_directions(payload: dict) -> Any:
        return {
            "agent": aurora_bound_agent.name,
            "context": AURORA_CONTEXT,
            "pid": payload["pid"],
            "kind": payload.get("type"),
        }

    @agent.keyed_receive("overlay", key_by=overlay_key, priority=(4,), seq_by=overlay_seq)
    async def receive_overlay(payload: dict) -> Any:
        return {
            "agent": aurora_bound_agent.name,
            "context": AURORA_CONTEXT,
            "pid": payload["pid"],
            "seq": payload["seq"],
        }

    @agent.send("gm/replies", multi=True, on_actions={Action.STAY})
    async def drain_replies() -> Any:
        return [
            {"agent": aurora_bound_agent.name, "kind": "reply", "index": 1},
            {"agent": aurora_bound_agent.name, "kind": "reply", "index": 2},
        ]

    @agent.send("gm/reply", on_actions={Action.TEST})
    async def send_world() -> Any:
        return {
            "agent": aurora_bound_agent.name,
            "context": AURORA_CONTEXT,
            "kind": "world",
        }


def _assert_mixed_agent_runtime(client, *, expected_name):
    assert client.loop.run_until_complete(client._upload_states({"seed": True})) == {
        "agent": expected_name,
        "context": AURORA_CONTEXT,
        "payload": {"seed": True},
    }
    assert client.loop.run_until_complete(client._download_states({"peer": "alpha"})) == {
        "agent": expected_name,
        "context": AURORA_CONTEXT,
        "payload": {"peer": "alpha"},
    }
    assert client.loop.run_until_complete(
        client.receiving_hooks[(1,)]({"content": {"pid": "player-1", "type": "tick"}})
    ) == {"pid": "player-1", "type": "tick"}
    assert client.loop.run_until_complete(client.receiver_index["audit"].fn({"kind": "audit"})) == {
        "agent": expected_name,
        "context": AURORA_CONTEXT,
        "payload": {"kind": "audit"},
    }

    directions = client.receiver_index["directions"]
    assert directions.priority == (3,)
    assert client.loop.run_until_complete(directions.fn({"pid": "player-1", "type": "tick"})) == {
        "agent": expected_name,
        "context": AURORA_CONTEXT,
        "pid": "player-1",
        "kind": "tick",
    }

    overlay = client.receiver_index["overlay"]
    assert overlay.priority == (4,)
    assert client.loop.run_until_complete(overlay.fn({"pid": "player-1", "seq": 1})) == {
        "agent": expected_name,
        "context": AURORA_CONTEXT,
        "pid": "player-1",
        "seq": 1,
    }
    assert client.loop.run_until_complete(overlay.fn({"pid": "player-1", "seq": 1})) is None
    assert client.loop.run_until_complete(overlay.fn({"pid": "player-1", "seq": 2})) == {
        "agent": expected_name,
        "context": AURORA_CONTEXT,
        "pid": "player-1",
        "seq": 2,
    }

    multi_sender = client.sender_index["gm/replies"][0]
    assert multi_sender.multi is True
    assert multi_sender.actions == {Action.STAY}
    assert client.loop.run_until_complete(multi_sender.fn()) == [
        {"agent": expected_name, "kind": "reply", "index": 1},
        {"agent": expected_name, "kind": "reply", "index": 2},
    ]

    single_sender = client.sender_index["gm/reply"][0]
    assert single_sender.multi is False
    assert single_sender.actions == {Action.TEST}
    assert client.loop.run_until_complete(single_sender.fn()) == {
        "agent": expected_name,
        "context": AURORA_CONTEXT,
        "kind": "world",
    }


def test_aurora_agent_registers_full_mixed_stack_and_exports_dna():
    agent = SummonerAgent(name="aurora-mixed")
    previous = _bind_agent(agent)

    try:
        _register_mixed_handlers(agent)
        _wait_for_registration(agent)

        _assert_mixed_agent_runtime(agent, expected_name="aurora-mixed")

        aurora_entries = json.loads(agent.dna())
        assert [entry["type"] for entry in aurora_entries] == [
            "upload_states",
            "download_states",
            "receive",
            "aurora:keyed_receive",
            "aurora:keyed_receive",
            "send",
            "send",
            "hook",
        ]
        assert sum(entry["type"] == "aurora:keyed_receive" for entry in aurora_entries) == 2
        assert any(entry["type"] == "receive" and entry["route"] == "audit" for entry in aurora_entries)
        assert any(
            entry["type"] == "send" and entry["route"] == "gm/replies" and entry["multi"] is True
            for entry in aurora_entries
        )
        assert agent.dna() == agent.dna(flavor="aurora")

        with pytest.raises(RuntimeError):
            agent.core_dna()

        lossy_core_entries = json.loads(agent.dna(flavor="core", allow_lossy=True))
        assert sum(entry["type"] == "receive" for entry in lossy_core_entries) == 3
        assert all(entry["type"] != "aurora:keyed_receive" for entry in lossy_core_entries)

        with pytest.raises(ValueError):
            agent.dna(flavor="unknown")
    finally:
        _restore_agent(previous)
        _close_clients(agent)


def test_keyed_receive_serializes_messages_for_same_key():
    agent = SummonerAgent(name="aurora-serial")

    try:
        started = []
        first_started = asyncio.Event()
        release_first = asyncio.Event()

        @agent.keyed_receive("serial", key_by="pid")
        async def handle(payload: dict) -> Any:
            started.append(payload["seq"])
            if payload["seq"] == 1:
                first_started.set()
                await release_first.wait()
            return payload["seq"]

        _wait_for_registration(agent)
        receiver = agent.receiver_index["serial"]

        async def scenario():
            first = asyncio.create_task(receiver.fn({"pid": "A", "seq": 1}))
            await asyncio.wait_for(first_started.wait(), timeout=0.2)

            second = asyncio.create_task(receiver.fn({"pid": "A", "seq": 2}))
            await asyncio.sleep(0.01)

            assert started == [1]
            assert not second.done()

            release_first.set()
            return await asyncio.gather(first, second)

        assert agent.loop.run_until_complete(scenario()) == [1, 2]
        assert started == [1, 2]
    finally:
        _close_clients(agent)


def test_keyed_receive_allows_parallel_processing_for_different_keys():
    agent = SummonerAgent(name="aurora-parallel")

    try:
        started = set()
        both_started = asyncio.Event()
        release = asyncio.Event()

        @agent.keyed_receive("parallel", key_by="pid")
        async def handle(payload: dict) -> Any:
            started.add(payload["pid"])
            if len(started) == 2:
                both_started.set()
            await release.wait()
            return payload["pid"]

        _wait_for_registration(agent)
        receiver = agent.receiver_index["parallel"]

        async def scenario():
            first = asyncio.create_task(receiver.fn({"pid": "A"}))
            second = asyncio.create_task(receiver.fn({"pid": "B"}))

            await asyncio.wait_for(both_started.wait(), timeout=0.2)
            assert started == {"A", "B"}
            assert not first.done()
            assert not second.done()

            release.set()
            return await asyncio.gather(first, second)

        assert agent.loop.run_until_complete(scenario()) == ["A", "B"]
    finally:
        _close_clients(agent)


def test_keyed_receive_drops_missing_keys_and_stale_sequences():
    agent = SummonerAgent(name="aurora-seq")

    try:
        accepted = []

        @agent.keyed_receive("overlay", key_by="pid", seq_by="seq")
        async def handle(payload: dict) -> Any:
            accepted.append((payload["pid"], payload["seq"]))
            return payload["seq"]

        _wait_for_registration(agent)
        receiver = agent.receiver_index["overlay"]

        assert agent.loop.run_until_complete(receiver.fn({"seq": 1})) is None
        assert agent.loop.run_until_complete(receiver.fn({"pid": "A", "seq": 1})) == 1
        assert agent.loop.run_until_complete(receiver.fn({"pid": "A", "seq": 1})) is None
        assert agent.loop.run_until_complete(receiver.fn({"pid": "A", "seq": 0})) is None
        assert agent.loop.run_until_complete(receiver.fn({"pid": "A", "seq": 2})) == 2
        assert agent.loop.run_until_complete(receiver.fn({"pid": "B", "seq": 1})) == 1

        assert accepted == [("A", 1), ("A", 2), ("B", 1)]
    finally:
        _close_clients(agent)


def test_keyed_receive_validates_arguments_and_handlers():
    agent = SummonerAgent(name="aurora-validation")

    try:
        with pytest.raises(TypeError):
            agent.keyed_receive(123, key_by="pid")

        with pytest.raises(ValueError):
            agent.keyed_receive("overlay", key_by=None)

        with pytest.raises(TypeError):
            @agent.keyed_receive("overlay", key_by="pid")
            def sync_handler(payload):
                return payload

        with pytest.raises(TypeError):
            @agent.keyed_receive("overlay", key_by="pid")
            async def wrong_arity(payload, extra):
                return payload

        with pytest.raises(ValueError):
            @agent.keyed_receive("overlay", key_by="pid", priority="high")
            async def bad_priority(payload):
                return payload
    finally:
        _close_clients(agent)


def test_agent_merger_preserves_mixed_aurora_behavior_and_rebinds_globals():
    source = SummonerAgent(name="aurora-source")
    merged = None
    previous = _bind_agent(source)

    try:
        _register_mixed_handlers(source)
        _wait_for_registration(source)

        merged = AgentMerger([source], name="aurora-merged", close_subclients=False)
        merged.initiate_all()
        _wait_for_registration(merged)

        _assert_mixed_agent_runtime(merged, expected_name="aurora-merged")

        merged_entries = json.loads(merged.dna())
        assert sum(entry["type"] == "aurora:keyed_receive" for entry in merged_entries) == 2
        assert any(entry["type"] == "receive" and entry["route"] == "audit" for entry in merged_entries)
    finally:
        _restore_agent(previous)
        _close_clients(source, merged)


def test_agent_translation_preserves_mixed_aurora_behavior_with_callable_extractors():
    source = SummonerAgent(name="aurora-translate-source")
    translated = None
    previous = _bind_agent(source)

    try:
        _register_mixed_handlers(source, callable_extractors=True)
        _wait_for_registration(source)

        dna_entries = json.loads(source.dna(include_context=True))
        assert dna_entries[0]["type"] == "__context__"
        assert dna_entries[0]["var_name"] == _BOUND_AGENT_NAME
        assert dna_entries[0]["globals"]["AURORA_CONTEXT"] == AURORA_CONTEXT

        translated = AgentTranslation(dna_entries, name="aurora-translated")
        translated.initiate_all()
        _wait_for_registration(translated)

        _assert_mixed_agent_runtime(translated, expected_name="aurora-translated")

        translated_entries = json.loads(translated.dna())
        keyed_entries = [entry for entry in translated_entries if entry["type"] == "aurora:keyed_receive"]
        assert len(keyed_entries) == 2
        assert all(entry["key_by_kind"] == "callable" for entry in keyed_entries)
        assert any(entry["seq_by_kind"] == "callable" for entry in keyed_entries)
    finally:
        _restore_agent(previous)
        _close_clients(source, translated)


def test_agent_merger_rebuilds_callable_extractors_from_dna_source():
    source = SummonerAgent(name="aurora-dna-source")
    merged = None
    previous = _bind_agent(source)

    try:
        _register_mixed_handlers(source, callable_extractors=True)
        _wait_for_registration(source)

        dna_entries = json.loads(source.dna(include_context=True))
        for entry in dna_entries:
            if entry.get("type") != "aurora:keyed_receive":
                continue

            entry["key_by_name"] = "missing.module:rebuilt_pid"
            entry["key_by_source"] = "def rebuilt_pid(payload):\n    return payload['pid']\n"

            if entry["route"] == "overlay":
                entry["seq_by_name"] = "missing.module:rebuilt_seq"
                entry["seq_by_source"] = "def rebuilt_seq(payload):\n    return payload['seq']\n"

        merged = AgentMerger([dna_entries], name="aurora-merged-dna", close_subclients=False)
        merged.initiate_all()
        _wait_for_registration(merged)

        _assert_mixed_agent_runtime(merged, expected_name="aurora-merged-dna")
    finally:
        _restore_agent(previous)
        _close_clients(source, merged)


def test_keyed_receive_supports_attribute_payloads_and_drops_unhashable_keys():
    agent = SummonerAgent(name="aurora-attr")

    class Payload:
        def __init__(self, pid, seq):
            self.pid = pid
            self.seq = seq

    try:
        accepted = []

        @agent.keyed_receive("attr", key_by="pid", seq_by="seq")
        async def handle(payload: Any) -> Any:
            accepted.append((payload.pid, payload.seq))
            return payload.seq

        _wait_for_registration(agent)
        receiver = agent.receiver_index["attr"]

        assert agent.loop.run_until_complete(receiver.fn(Payload("A", 1))) == 1
        assert agent.loop.run_until_complete(receiver.fn(Payload(["A"], 2))) is None
        assert accepted == [("A", 1)]
    finally:
        _close_clients(agent)


def test_keyed_receive_handles_callable_extractor_failures():
    agent = SummonerAgent(name="aurora-extractors")

    def stable_key(payload):
        return payload["pid"]

    def exploding_key(payload):
        raise RuntimeError("boom")

    def exploding_seq(payload):
        raise RuntimeError("boom")

    try:
        dropped = []
        seq_passthrough = []

        @agent.keyed_receive("drop-on-key-error", key_by=exploding_key)
        async def dropped_handler(payload: dict) -> Any:
            dropped.append(payload["pid"])
            return payload["pid"]

        @agent.keyed_receive("seq-error", key_by=stable_key, seq_by=exploding_seq)
        async def seq_handler(payload: dict) -> Any:
            seq_passthrough.append(payload["seq"])
            return payload["seq"]

        _wait_for_registration(agent)

        dropped_receiver = agent.receiver_index["drop-on-key-error"]
        seq_receiver = agent.receiver_index["seq-error"]

        assert agent.loop.run_until_complete(dropped_receiver.fn({"pid": "A"})) is None
        assert dropped == []

        assert agent.loop.run_until_complete(seq_receiver.fn({"pid": "A", "seq": 1})) == 1
        assert agent.loop.run_until_complete(seq_receiver.fn({"pid": "A", "seq": 1})) == 1
        assert seq_passthrough == [1, 1]
    finally:
        _close_clients(agent)


def test_async_keyed_mutex_cleans_up_cancelled_waiters():
    mutex = AsyncKeyedMutex()

    async def scenario():
        holder_started = asyncio.Event()
        release_holder = asyncio.Event()

        async def holder():
            async with mutex.lock("same-key"):
                holder_started.set()
                await release_holder.wait()

        async def waiter():
            async with mutex.lock("same-key"):
                return "waiter"

        first = asyncio.create_task(holder())
        await asyncio.wait_for(holder_started.wait(), timeout=0.2)

        second = asyncio.create_task(waiter())
        await asyncio.sleep(0.01)
        assert mutex._refs["same-key"] == 2

        second.cancel()
        with pytest.raises(asyncio.CancelledError):
            await second

        assert mutex._refs["same-key"] == 1

        release_holder.set()
        await first

        assert mutex._locks == {}
        assert mutex._refs == {}

        async with mutex.lock("same-key"):
            assert mutex._refs["same-key"] == 1

        assert mutex._locks == {}
        assert mutex._refs == {}

    asyncio.run(scenario())


def test_keyed_receive_pressure_preserves_per_key_exclusion_and_replay_rules():
    agent = SummonerAgent(name="aurora-pressure")

    try:
        active_by_key = {}
        max_active_by_key = {}
        accepted_by_key = {}
        active_total = 0
        max_active_total = 0

        @agent.keyed_receive("pressure", key_by="pid", seq_by="seq")
        async def handle(payload: dict) -> Any:
            nonlocal active_total, max_active_total

            pid = payload["pid"]
            active_by_key[pid] = active_by_key.get(pid, 0) + 1
            max_active_by_key[pid] = max(max_active_by_key.get(pid, 0), active_by_key[pid])
            active_total += 1
            max_active_total = max(max_active_total, active_total)

            try:
                await asyncio.sleep(0.001)
                accepted_by_key.setdefault(pid, []).append(payload["seq"])
                return payload["seq"]
            finally:
                active_by_key[pid] -= 1
                active_total -= 1

        _wait_for_registration(agent)
        receiver = agent.receiver_index["pressure"]

        plans = {
            "A": [1, 1, 2, 3, 2, 4, 5, 5, 6, 4, 7, 8],
            "B": [1, 2, 2, 3, 1, 4, 6, 5, 6, 7, 7, 8],
            "C": [1, 1, 1, 2, 3, 3, 4, 2, 5, 6, 6, 7],
            "D": [1, 2, 3, 4, 5, 6, 7, 8, 8, 7, 9, 10],
        }

        expected_by_key = {}
        for pid, seqs in plans.items():
            last = None
            expected = []
            for seq in seqs:
                if last is None or seq > last:
                    expected.append(seq)
                    last = seq
            expected_by_key[pid] = expected

        payloads = []
        max_len = max(len(seqs) for seqs in plans.values())
        for index in range(max_len):
            for pid, seqs in plans.items():
                if index < len(seqs):
                    payloads.append({"pid": pid, "seq": seqs[index]})

        async def scenario():
            tasks = [asyncio.create_task(receiver.fn(payload)) for payload in payloads]
            return await asyncio.gather(*tasks)

        results = agent.loop.run_until_complete(scenario())
        processed = [result for result in results if result is not None]

        assert accepted_by_key == expected_by_key
        assert len(processed) == sum(len(seqs) for seqs in expected_by_key.values())
        assert all(max_active_by_key[pid] == 1 for pid in plans)
        assert max_active_total > 1
        assert agent._key_mutex is not None
        assert agent._key_mutex._locks == {}
        assert agent._key_mutex._refs == {}
    finally:
        _close_clients(agent)
