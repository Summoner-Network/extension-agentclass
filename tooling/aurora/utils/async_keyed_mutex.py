import asyncio

from typing import Hashable, Optional


class _KeyedMutexGuard:
    __slots__ = ("_mutex", "_key", "_lock")

    def __init__(self, mutex: "AsyncKeyedMutex", key: Hashable):
        self._mutex = mutex
        self._key = key
        self._lock: Optional[asyncio.Lock] = None

    async def __aenter__(self):
        lock = self._mutex._acquire_lock_ref(self._key)
        self._lock = lock
        try:
            await lock.acquire()
        except asyncio.CancelledError:
            self._mutex._release_lock_ref(self._key)
            raise
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self._lock is not None:
            self._lock.release()
        self._mutex._release_lock_ref(self._key)


class AsyncKeyedMutex:
    __slots__ = ("_locks", "_refs")

    def __init__(self):
        self._locks: dict[Hashable, asyncio.Lock] = {}
        self._refs: dict[Hashable, int] = {}

    def _acquire_lock_ref(self, key: Hashable) -> asyncio.Lock:
        # Aurora handlers run on a single event loop, so this bookkeeping
        # executes atomically until the await on `lock.acquire()`.
        lock = self._locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            self._locks[key] = lock
            self._refs[key] = 1
            return lock
        self._refs[key] += 1
        return lock

    def _release_lock_ref(self, key: Hashable) -> None:
        refs = self._refs.get(key)
        if refs is None:
            return

        refs -= 1
        if refs <= 0:
            self._locks.pop(key, None)
            self._refs.pop(key, None)
        else:
            self._refs[key] = refs

    def lock(self, key: Hashable) -> _KeyedMutexGuard:
        return _KeyedMutexGuard(self, key)
