import inspect
import json
import textwrap

from collections import OrderedDict
from importlib import import_module

from summoner.client import SummonerClient
from summoner.protocol.process import Receiver
from summoner.protocol.triggers import Event
from summoner.protocol.validation import _check_param_and_return
from summoner.utils import get_callable_source

from tooling.aurora.identity.host import IdentityHostMixin
from tooling.aurora.utils.async_keyed_mutex import AsyncKeyedMutex

from typing import Callable, Hashable, Any, Optional, Union


AURORA_KEYED_RECEIVE_TYPE = "aurora:keyed_receive"


def _resolve_callable_reference(
    globals_dict: dict[str, Any],
    ref: Optional[str],
) -> Optional[Callable[..., Any]]:
    if not isinstance(ref, str) or not ref:
        return None

    if ":" in ref:
        module_name, qualname = ref.split(":", 1)
        try:
            obj = import_module(module_name)
        except Exception:
            obj = None

        if obj is not None:
            try:
                for part in qualname.split("."):
                    if part == "<locals>":
                        return None
                    obj = getattr(obj, part)
                if callable(obj):
                    return obj
            except Exception:
                pass

        fallback_name = qualname.split(".")[-1]
        fallback = globals_dict.get(fallback_name)
        if callable(fallback):
            return fallback
        return None

    candidate = globals_dict.get(ref)
    if callable(candidate):
        return candidate
    return None


def _resolve_callable_reference_from_source(
    globals_dict: dict[str, Any],
    ref: Optional[str],
    source: Optional[str],
) -> Optional[Callable[..., Any]]:
    if not isinstance(source, str) or not source.strip():
        return None

    expected_name = None
    if isinstance(ref, str) and ref:
        if ":" in ref:
            _, qualname = ref.split(":", 1)
            if "<locals>" not in qualname:
                expected_name = qualname.split(".")[-1]
        else:
            expected_name = ref

    if not isinstance(expected_name, str) or not expected_name or expected_name == "<lambda>":
        return None

    try:
        if "__builtins__" not in globals_dict:
            globals_dict["__builtins__"] = __builtins__
        dedented_source = textwrap.dedent(source)
        exec(compile(dedented_source, filename="<aurora_extractor>", mode="exec"), globals_dict)
    except Exception:
        return None

    candidate = globals_dict.get(expected_name)
    if callable(candidate):
        try:
            candidate.__dna_source__ = dedented_source
        except Exception:
            pass
        return candidate
    return None


def _resolve_aurora_extractor_spec(
    globals_dict: dict[str, Any],
    kind: str,
    value: Optional[str],
    name: Optional[str],
    source: Optional[str],
    *,
    label: str,
) -> Union[None, str, Callable[..., Any]]:
    if kind == "none":
        return None

    if kind == "field":
        if not isinstance(value, str) or not value:
            raise ValueError(f"Invalid serialized {label} field extractor")
        return value

    if kind == "callable":
        resolved = _resolve_callable_reference(globals_dict, name)
        if not callable(resolved):
            resolved = _resolve_callable_reference_from_source(globals_dict, name, source)
        if callable(resolved):
            return resolved
        raise ValueError(
            f"Could not resolve serialized {label} callable {name!r} "
            "from available replay context"
        )

    raise ValueError(f"Unknown {label} kind {kind!r}")


class _AuroraMixin:

    release_name = "aurora"
    release_version = "beta.1.2.0"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._key_mutex: Optional[AsyncKeyedMutex] = None
        self._seq_seen: dict[tuple[str, Hashable], int] = {}
        self._seq_seen_bounded: dict[str, dict[Hashable, int]] = {}
        self._seq_seen_lru: dict[str, OrderedDict[Hashable, None]] = {}
        self._seq_seen_evictions: int = 0
        self._dna_aurora_receivers: list[dict[str, Any]] = []

    def _iter_registered_handler_functions(self):
        yield from super()._iter_registered_handler_functions()

        for dna in self._dna_aurora_receivers:
            key_by = dna.get("key_by")
            if callable(key_by):
                yield key_by

            seq_by = dna.get("seq_by")
            if callable(seq_by):
                yield seq_by

    def _normalize_receive_priority(
        self,
        priority: Union[int, tuple[int, ...]],
        *,
        decorator_name: str,
    ) -> tuple[int, ...]:
        if isinstance(priority, int):
            return (priority,)
        if isinstance(priority, tuple) and all(isinstance(p, int) for p in priority):
            return priority
        raise ValueError(
            f"Priority for {decorator_name} must be an integer or a tuple of integers "
            f"(got type {type(priority).__name__}: {priority!r})"
        )

    @staticmethod
    def _normalize_seq_history_max_entries(
        value: Optional[int],
    ) -> Optional[int]:
        if value is None:
            return None
        if isinstance(value, bool) or not isinstance(value, int):
            raise TypeError(
                "Argument `seq_history_max_entries` must be `None` or a positive integer. "
                f"Provided: {value!r}"
            )
        if value <= 0:
            raise ValueError(
                "Argument `seq_history_max_entries` must be positive when provided. "
                f"Provided: {value!r}"
            )
        return value

    def _serialize_extractor_spec(
        self,
        spec: Union[None, str, Callable[..., Any]],
        *,
        label: str,
        allow_none: bool = False,
    ) -> tuple[str, Optional[str], Optional[str], Optional[str]]:
        if spec is None:
            if allow_none:
                return ("none", None, None, None)
            raise ValueError(f"@keyed_receive requires {label}")

        if isinstance(spec, str):
            value = spec.strip()
            if not value:
                raise ValueError(f"@keyed_receive requires non-empty {label}")
            return ("field", value, None, None)

        if callable(spec):
            module_name = getattr(spec, "__module__", None)
            qualname = getattr(spec, "__qualname__", None)
            serialized_name = None
            source = None

            if isinstance(module_name, str) and module_name and isinstance(qualname, str) and qualname:
                serialized_name = f"{module_name}:{qualname}"
            else:
                fallback_name = getattr(spec, "__name__", None)
                if isinstance(fallback_name, str) and fallback_name:
                    serialized_name = fallback_name

            try:
                source = inspect.getsource(spec)
            except Exception:
                source = getattr(spec, "__dna_source__", None)
                if not (isinstance(source, str) and source.strip()):
                    source = None

            return ("callable", None, serialized_name, source)

        raise TypeError(
            f"Argument `{label}` must be a string or a callable. Provided: {spec!r}"
        )

    @staticmethod
    def _read_payload_field(payload: Any, field: str) -> Any:
        try:
            if isinstance(payload, dict):
                return payload.get(field)
            return getattr(payload, field, None)
        except Exception:
            return None

    @staticmethod
    def _coerce_hashable(value: Any) -> Optional[Hashable]:
        if value is None:
            return None
        try:
            hash(value)
        except Exception:
            return None
        return value

    def _build_key_extractor(
        self,
        key_by: Union[str, Callable[[Any], Hashable]],
    ) -> Callable[[Any], Optional[Hashable]]:
        if isinstance(key_by, str):
            field = key_by

            def _key(payload: Any) -> Optional[Hashable]:
                try:
                    if isinstance(payload, dict):
                        value = payload.get(field)
                    else:
                        value = getattr(payload, field, None)
                except Exception:
                    return None

                if value is None:
                    return None

                try:
                    hash(value)
                except Exception:
                    return None
                return value

            return _key

        callable_key_by = key_by

        def _key(payload: Any) -> Optional[Hashable]:
            try:
                value = callable_key_by(payload)
            except Exception:
                return None

            if value is None:
                return None

            try:
                hash(value)
            except Exception:
                return None
            return value

        return _key

    def _build_seq_extractor(
        self,
        seq_by: Union[None, str, Callable[[Any], int]],
    ) -> Optional[Callable[[Any], Optional[int]]]:
        if seq_by is None:
            return None

        if isinstance(seq_by, str):
            field = seq_by

            def _seq(payload: Any) -> Optional[int]:
                try:
                    if isinstance(payload, dict):
                        value = payload.get(field)
                    else:
                        value = getattr(payload, field, None)
                except Exception:
                    return None

                if value is None:
                    return None
                try:
                    return int(value)
                except (TypeError, ValueError):
                    return None

            return _seq

        callable_seq_by = seq_by

        def _seq(payload: Any) -> Optional[int]:
            try:
                return int(callable_seq_by(payload))
            except Exception:
                return None

        return _seq

    def _ensure_bounded_route_seq_state(
        self,
        route: str,
    ) -> tuple[dict[Hashable, int], OrderedDict[Hashable, None]]:
        route_seq_seen = self._seq_seen_bounded.get(route)
        if route_seq_seen is None:
            route_seq_seen = {}
            self._seq_seen_bounded[route] = route_seq_seen

        route_seq_lru = self._seq_seen_lru.get(route)
        if route_seq_lru is None:
            route_seq_lru = OrderedDict((key, None) for key in route_seq_seen)
            self._seq_seen_lru[route] = route_seq_lru
        return route_seq_seen, route_seq_lru

    def clear_keyed_receive_replay_state(
        self,
        route: Optional[str] = None,
    ) -> None:
        if route is None:
            self._seq_seen.clear()
            for route_seq_seen in self._seq_seen_bounded.values():
                route_seq_seen.clear()
            for route_seq_lru in self._seq_seen_lru.values():
                route_seq_lru.clear()
            return

        normalized_route = route.strip()
        for lock_key in tuple(self._seq_seen):
            if lock_key[0] == normalized_route:
                self._seq_seen.pop(lock_key, None)

        route_seq_seen = self._seq_seen_bounded.get(normalized_route)
        if route_seq_seen is not None:
            route_seq_seen.clear()

        route_seq_lru = self._seq_seen_lru.get(normalized_route)
        if route_seq_lru is not None:
            route_seq_lru.clear()

    def keyed_receive_replay_stats(self) -> dict[str, int]:
        routes = {route for route, _ in self._seq_seen}
        entries = len(self._seq_seen)
        for route, route_seq_seen in self._seq_seen_bounded.items():
            count = len(route_seq_seen)
            entries += count
            if count > 0:
                routes.add(route)

        return {
            "routes": len(routes),
            "entries": entries,
            "evictions": self._seq_seen_evictions,
        }

    async def _register_keyed_receiver(
        self,
        *,
        fn: Callable[[Any], Any],
        route: str,
        tuple_priority: tuple[int, ...],
        key_by: Union[str, Callable[[Any], Hashable]],
        seq_by: Union[None, str, Callable[[Any], int]],
        seq_history_max_entries: Optional[int],
    ) -> None:
        if self._key_mutex is None:
            self._key_mutex = AsyncKeyedMutex()

        keyed_mutex = self._key_mutex
        logger = self.logger
        raw_fn = fn
        key_fn = self._build_key_extractor(key_by)
        seq_fn = self._build_seq_extractor(seq_by)
        seq_seen = self._seq_seen
        parsed_route = None
        normalized_route = route

        if self._flow.in_use:
            try:
                parsed_route = self._flow.parse_route(route)
                normalized_route = str(parsed_route)
            except Exception as e:
                self.logger.warning(
                    f"@keyed_receive: could not parse route {route!r} while flow is enabled; "
                    f"registering raw route. Error: {type(e).__name__}: {e}"
                )
                parsed_route = None
                normalized_route = route

        mutex_lock = keyed_mutex.lock
        route_name = normalized_route

        if seq_fn is None:
            async def wrapped(payload: Any):
                key = key_fn(payload)
                if key is None:
                    logger.debug(
                        "Dropped message on route %r: missing/invalid key",
                        route_name,
                    )
                    return None

                lock_key = (route_name, key)
                async with mutex_lock(lock_key):
                    return await raw_fn(payload)
        elif seq_history_max_entries is None:
            async def wrapped(payload: Any):
                key = key_fn(payload)
                if key is None:
                    logger.debug(
                        "Dropped message on route %r: missing/invalid key",
                        route_name,
                    )
                    return None

                lock_key = (route_name, key)
                async with mutex_lock(lock_key):
                    seq = seq_fn(payload)
                    if seq is not None:
                        last = seq_seen.get(lock_key)
                        if last is not None and seq <= last:
                            logger.debug(
                                "Dropped replay on route %r key %r: seq %s <= last %s",
                                route_name,
                                key,
                                seq,
                                last,
                            )
                            return None
                        seq_seen[lock_key] = seq

                    return await raw_fn(payload)
        else:
            route_seq_seen, route_seq_lru = self._ensure_bounded_route_seq_state(route_name)
            max_entries = seq_history_max_entries

            async def wrapped(payload: Any):
                key = key_fn(payload)
                if key is None:
                    logger.debug(
                        "Dropped message on route %r: missing/invalid key",
                        route_name,
                    )
                    return None

                lock_key = (route_name, key)
                async with mutex_lock(lock_key):
                    seq = seq_fn(payload)
                    if seq is not None:
                        last = route_seq_seen.get(key)
                        if last is not None:
                            route_seq_lru[key] = None
                            route_seq_lru.move_to_end(key)
                            if seq <= last:
                                logger.debug(
                                    "Dropped replay on route %r key %r: seq %s <= last %s",
                                    route_name,
                                    key,
                                    seq,
                                    last,
                                )
                                return None

                        route_seq_seen[key] = seq
                        route_seq_lru[key] = None
                        route_seq_lru.move_to_end(key)

                        while len(route_seq_lru) > max_entries:
                            evicted_key, _ = route_seq_lru.popitem(last=False)
                            route_seq_seen.pop(evicted_key, None)
                            self._seq_seen_evictions += 1

                    return await raw_fn(payload)

        receiver = Receiver(fn=wrapped, priority=tuple_priority)

        async with self.routes_lock:
            if normalized_route in self.receiver_index:
                self.logger.warning(f"Route '{normalized_route}' already exists. Overwriting.")

            if self._flow.in_use and parsed_route is not None:
                self.receiver_parsed_routes[normalized_route] = parsed_route
            self.receiver_index[normalized_route] = receiver

    def _route_key_for_dna(self, route: str) -> str:
        try:
            if self._flow.in_use:
                route_key = str(self._flow.parse_route(route))
            else:
                route_key = route
        except Exception:
            route_key = route

        return "".join(str(route_key).split())

    def _build_aurora_dna_entry(self, dna: dict[str, Any]) -> dict[str, Any]:
        fn = dna["fn"]
        return {
            "type": AURORA_KEYED_RECEIVE_TYPE,
            "route": dna["route"],
            "route_key": self._route_key_for_dna(dna["route"]),
            "priority": dna["priority"],
            "key_by_kind": dna["key_by_kind"],
            "key_by_value": dna["key_by_value"],
            "key_by_name": dna["key_by_name"],
            "key_by_source": dna.get("key_by_source", None),
            "seq_by_kind": dna["seq_by_kind"],
            "seq_by_value": dna["seq_by_value"],
            "seq_by_name": dna["seq_by_name"],
            "seq_by_source": dna.get("seq_by_source", None),
            "seq_history_max_entries": dna.get("seq_history_max_entries", None),
            "source": get_callable_source(fn, dna.get("source")),
            "module": fn.__module__,
            "fn_name": fn.__name__,
        }

    @staticmethod
    def _insert_receive_entries(
        entries: list[dict[str, Any]],
        receive_entries: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        if not receive_entries:
            return entries

        insert_at = 1 if entries and entries[0].get("type") == "__context__" else 0
        while insert_at < len(entries) and entries[insert_at].get("type") in {
            "upload_states",
            "download_states",
            "receive",
        }:
            insert_at += 1

        entries[insert_at:insert_at] = receive_entries
        return entries

    def core_dna(
        self,
        include_context: bool = False,
        *,
        allow_lossy: bool = False,
    ) -> str:
        entries = json.loads(super().dna(include_context=include_context))
        if not self._dna_aurora_receivers:
            return json.dumps(entries)

        if not allow_lossy:
            raise RuntimeError(
                "Aurora keyed receivers require Aurora DNA. "
                "Use agent.dna(..., flavor='aurora') or core_dna(..., allow_lossy=True)."
            )

        lossy_receives = []
        for dna in self._dna_aurora_receivers:
            entry = self._build_aurora_dna_entry(dna)
            lossy_receives.append({
                "type": "receive",
                "route": entry["route"],
                "route_key": entry["route_key"],
                "priority": entry["priority"],
                "source": entry["source"],
                "module": entry["module"],
                "fn_name": entry["fn_name"],
            })

        return json.dumps(self._insert_receive_entries(entries, lossy_receives))

    def aurora_dna(self, include_context: bool = False) -> str:
        entries = json.loads(super().dna(include_context=include_context))
        aurora_entries = [
            self._build_aurora_dna_entry(dna)
            for dna in self._dna_aurora_receivers
        ]
        return json.dumps(self._insert_receive_entries(entries, aurora_entries))

    def dna(
        self,
        include_context: bool = False,
        *,
        flavor: str = "aurora",
        allow_lossy: bool = False,
    ) -> str:
        if flavor == "aurora":
            return self.aurora_dna(include_context=include_context)
        if flavor == "core":
            return self.core_dna(
                include_context=include_context,
                allow_lossy=allow_lossy,
            )
        raise ValueError(f"Unknown DNA flavor {flavor!r}")

    def keyed_receive(
        self,
        route: str,
        key_by: Union[str, Callable[[Any], Hashable]],
        priority: Union[int, tuple[int, ...]] = (),
        seq_by: Union[None, str, Callable[[Any], int]] = None,
        seq_history_max_entries: Optional[int] = None,
    ):
        if not isinstance(route, str):
            raise TypeError(f"Argument `route` must be string. Provided: {route}")
        route = route.strip()
        normalized_seq_history_max_entries = self._normalize_seq_history_max_entries(
            seq_history_max_entries
        )
        if normalized_seq_history_max_entries is not None and seq_by is None:
            raise ValueError("Argument `seq_history_max_entries` requires `seq_by`")

        key_by_kind, key_by_value, key_by_name, key_by_source = self._serialize_extractor_spec(
            key_by,
            label="key_by",
        )
        seq_by_kind, seq_by_value, seq_by_name, seq_by_source = self._serialize_extractor_spec(
            seq_by,
            label="seq_by",
            allow_none=True,
        )

        def decorator(fn: Callable[[Any], Any]):
            if not inspect.iscoroutinefunction(fn):
                raise TypeError(f"@keyed_receive handler '{fn.__name__}' must be async")

            sig = inspect.signature(fn)
            if len(sig.parameters) != 1:
                raise TypeError(
                    f"@keyed_receive '{fn.__name__}' must accept exactly one argument (payload)"
                )

            _check_param_and_return(
                fn,
                decorator_name="@keyed_receive",
                allow_param=(Any, str, dict),
                allow_return=(type(None), Event, Any),
                logger=self.logger,
                expected_params=1,
            )

            tuple_priority = self._normalize_receive_priority(
                priority,
                decorator_name="@keyed_receive",
            )

            self._dna_aurora_receivers.append({
                "fn": fn,
                "route": route,
                "priority": tuple_priority,
                "key_by": key_by,
                "key_by_kind": key_by_kind,
                "key_by_value": key_by_value,
                "key_by_name": key_by_name,
                "key_by_source": key_by_source,
                "seq_by": seq_by,
                "seq_by_kind": seq_by_kind,
                "seq_by_value": seq_by_value,
                "seq_by_name": seq_by_name,
                "seq_by_source": seq_by_source,
                "seq_history_max_entries": normalized_seq_history_max_entries,
                "source": inspect.getsource(fn),
                "module": fn.__module__,
                "fn_name": fn.__name__,
            })

            self._schedule_registration(
                self._register_keyed_receiver(
                    fn=fn,
                    route=route,
                    tuple_priority=tuple_priority,
                    key_by=key_by,
                    seq_by=seq_by,
                    seq_history_max_entries=normalized_seq_history_max_entries,
                )
            )
            return fn

        return decorator


class SummonerAgent(IdentityHostMixin, _AuroraMixin, SummonerClient):
    pass
