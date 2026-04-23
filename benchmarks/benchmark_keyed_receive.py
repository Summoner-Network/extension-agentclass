import argparse
import asyncio
import os
import statistics
import sys
import time

from dataclasses import dataclass
from typing import Any, Optional

target_path = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
if target_path not in sys.path:
    sys.path.insert(0, target_path)

from tooling.aurora import SummonerAgent


@dataclass(frozen=True)
class BenchmarkCase:
    name: str
    mode: str
    use_seq: bool
    keys: int
    replay_stride: int


def _wait_for_registration(client) -> None:
    client.loop.run_until_complete(client._wait_for_registration())


def _build_payloads(
    *,
    messages: int,
    keys: int,
    use_seq: bool,
    replay_stride: int,
) -> list[dict[str, Any]]:
    payloads: list[dict[str, Any]] = []
    next_seq_by_key = [1] * keys

    for index in range(messages):
        key_index = index % keys
        payload = {
            "pid": f"player-{key_index}",
            "index": index,
        }

        if use_seq:
            next_seq = next_seq_by_key[key_index]
            if replay_stride > 0 and next_seq > 1 and index % replay_stride == 0:
                payload["seq"] = next_seq - 1
            else:
                payload["seq"] = next_seq
                next_seq_by_key[key_index] = next_seq + 1

        payloads.append(payload)

    return payloads


def _make_agent(*, use_seq: bool, handler_sleep: float) -> tuple[SummonerAgent, Any]:
    return _make_agent_with_mode(
        mode="keyed",
        use_seq=use_seq,
        handler_sleep=handler_sleep,
        seq_history_max_entries=None,
    )


def _make_agent_with_mode(
    *,
    mode: str,
    use_seq: bool,
    handler_sleep: float,
    seq_history_max_entries: Optional[int],
) -> tuple[SummonerAgent, Any]:
    agent = SummonerAgent(name="aurora-benchmark")

    if mode not in {"keyed", "receive"}:
        raise ValueError(f"Unknown benchmark mode {mode!r}")

    if mode == "keyed":
        if use_seq:
            @agent.keyed_receive(
                "bench",
                key_by="pid",
                seq_by="seq",
                seq_history_max_entries=seq_history_max_entries,
            )
            async def handle(payload: dict) -> Any:
                if handler_sleep > 0:
                    await asyncio.sleep(handler_sleep)
                return payload["seq"]
        else:
            @agent.keyed_receive("bench", key_by="pid")
            async def handle(payload: dict) -> Any:
                if handler_sleep > 0:
                    await asyncio.sleep(handler_sleep)
                return payload["index"]
    else:
        @agent.receive("bench")
        async def handle(payload: dict) -> Any:
            if handler_sleep > 0:
                await asyncio.sleep(handler_sleep)
            if use_seq:
                return payload["seq"]
            return payload["index"]

    _wait_for_registration(agent)
    return agent, agent.receiver_index["bench"]


async def _run_payloads(
    receiver,
    payloads: list[dict[str, Any]],
    *,
    batch_size: int,
) -> tuple[float, int]:
    accepted = 0
    started_at = time.perf_counter()

    for start in range(0, len(payloads), batch_size):
        batch = payloads[start:start + batch_size]
        results = await asyncio.gather(*(receiver.fn(payload) for payload in batch))
        accepted += sum(result is not None for result in results)

    elapsed = time.perf_counter() - started_at
    return elapsed, accepted


def _format_rate(value: float) -> str:
    return f"{value:,.0f}"


def run_case(
    case: BenchmarkCase,
    *,
    messages: int,
    rounds: int,
    warmup: int,
    batch_size: int,
    handler_sleep: float,
    seq_history_max_entries: Optional[int],
) -> dict[str, Any]:
    payloads = _build_payloads(
        messages=messages,
        keys=case.keys,
        use_seq=case.use_seq,
        replay_stride=case.replay_stride,
    )
    agent, receiver = _make_agent_with_mode(
        mode=case.mode,
        use_seq=case.use_seq,
        handler_sleep=handler_sleep,
        seq_history_max_entries=(
            seq_history_max_entries
            if case.mode == "keyed" and case.use_seq
            else None
        ),
    )
    durations: list[float] = []
    accepted = 0

    try:
        for round_index in range(warmup + rounds):
            agent.clear_keyed_receive_replay_state()
            elapsed, accepted = agent.loop.run_until_complete(
                _run_payloads(receiver, payloads, batch_size=batch_size)
            )
            if round_index >= warmup:
                durations.append(elapsed)
    finally:
        agent.loop.close()

    best = min(durations)
    mean = statistics.mean(durations)
    dropped = len(payloads) - accepted
    replay_stats = agent.keyed_receive_replay_stats()

    return {
        "case": case.name,
        "mode": case.mode,
        "messages": len(payloads),
        "keys": case.keys,
        "accepted": accepted,
        "dropped": dropped,
        "best_seconds": best,
        "mean_seconds": mean,
        "best_messages_per_second": len(payloads) / best,
        "best_accepted_per_second": accepted / best,
        "replay_entries": replay_stats["entries"],
        "replay_evictions": replay_stats["evictions"],
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Benchmark Aurora keyed_receive under burst load.")
    parser.add_argument("--messages", type=int, default=20000, help="Messages to push through each case.")
    parser.add_argument("--keys", type=int, default=128, help="Distinct keys for the many-key cases.")
    parser.add_argument("--rounds", type=int, default=5, help="Measured rounds per case.")
    parser.add_argument("--warmup", type=int, default=1, help="Warmup rounds per case.")
    parser.add_argument("--batch-size", type=int, default=2000, help="Concurrent tasks launched per batch.")
    parser.add_argument(
        "--handler-sleep",
        type=float,
        default=0.0,
        help="Optional async sleep inside the handler to simulate heavier GM work.",
    )
    parser.add_argument(
        "--seq-history-max-entries",
        type=int,
        default=None,
        help="Optional per-route replay history cap for seq-based keyed_receive handlers.",
    )
    parser.add_argument(
        "--compare-receive",
        action="store_true",
        help="Add plain @receive rows as an unsafe throughput baseline.",
    )
    args = parser.parse_args(argv)

    cases = [
        BenchmarkCase(name="same_key_no_seq", mode="keyed", use_seq=False, keys=1, replay_stride=0),
        BenchmarkCase(name="same_key_seq", mode="keyed", use_seq=True, keys=1, replay_stride=0),
        BenchmarkCase(name="many_keys_seq", mode="keyed", use_seq=True, keys=max(1, args.keys), replay_stride=0),
        BenchmarkCase(name="many_keys_replay", mode="keyed", use_seq=True, keys=max(1, args.keys), replay_stride=3),
    ]
    if args.compare_receive:
        cases.extend([
            BenchmarkCase(name="same_key_no_seq", mode="receive", use_seq=False, keys=1, replay_stride=0),
            BenchmarkCase(name="same_key_seq", mode="receive", use_seq=True, keys=1, replay_stride=0),
            BenchmarkCase(name="many_keys_seq", mode="receive", use_seq=True, keys=max(1, args.keys), replay_stride=0),
            BenchmarkCase(name="many_keys_replay", mode="receive", use_seq=True, keys=max(1, args.keys), replay_stride=3),
        ])

    print(
        "mode     case                  messages  keys  accepted  dropped  best_s   mean_s   msg/s    accepted/s  hist  evict"
    )
    print(
        "-------  --------------------  --------  ----  --------  -------  -------  -------  -------  ----------  ----  -----"
    )

    for case in cases:
        result = run_case(
            case,
            messages=args.messages,
            rounds=args.rounds,
            warmup=args.warmup,
            batch_size=max(1, args.batch_size),
            handler_sleep=max(0.0, args.handler_sleep),
            seq_history_max_entries=args.seq_history_max_entries,
        )
        print(
            f"{result['mode']:<7}  "
            f"{result['case']:<20}  "
            f"{result['messages']:>8}  "
            f"{result['keys']:>4}  "
            f"{result['accepted']:>8}  "
            f"{result['dropped']:>7}  "
            f"{result['best_seconds']:>7.4f}  "
            f"{result['mean_seconds']:>7.4f}  "
            f"{_format_rate(result['best_messages_per_second']):>7}  "
            f"{_format_rate(result['best_accepted_per_second']):>10}  "
            f"{result['replay_entries']:>4}  "
            f"{result['replay_evictions']:>5}"
        )

    if args.compare_receive:
        print()
        print(
            "Note: receive rows are an unsafe baseline. They measure plain @receive throughput "
            "without per-key serialization or replay dropping."
        )

    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
