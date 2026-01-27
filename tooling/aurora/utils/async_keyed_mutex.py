import asyncio
from typing import Hashable

class AsyncKeyedMutex:
    def __init__(self):
        self._locks: dict[Hashable, asyncio.Lock] = {}
        self._refs: dict[Hashable, int] = {}
        self._guard = asyncio.Lock()

    def lock(self, key: Hashable):
        mutex = self
        class _Guard:
            
            # async def __aenter__(self_nonlocal):
            #     async with mutex._guard:
            #         lock = mutex._locks.get(key)
            #         if lock is None:
            #             lock = asyncio.Lock()
            #             mutex._locks[key] = lock
            #             mutex._refs[key] = 0
            #         mutex._refs[key] += 1
            #         self_nonlocal._lock = lock
            #     await self_nonlocal._lock.acquire()

            async def __aenter__(self_nonlocal):
                async with mutex._guard:
                    lock = mutex._locks.get(key)
                    if lock is None:
                        lock = asyncio.Lock()
                        mutex._locks[key] = lock
                        mutex._refs[key] = 0
                    mutex._refs[key] += 1
                    self_nonlocal._lock = lock
                try:
                    await self_nonlocal._lock.acquire()
                except asyncio.CancelledError:
                    async with mutex._guard:
                        mutex._refs[key] -= 1
                        if mutex._refs[key] == 0:
                            del mutex._locks[key]
                            del mutex._refs[key]
                    raise

            async def __aexit__(self_nonlocal, exc_type, exc, tb): # keep inputs to align with lock logic
                self_nonlocal._lock.release()
                async with mutex._guard:
                    mutex._refs[key] -= 1
                    if mutex._refs[key] == 0:
                        del mutex._locks[key]
                        del mutex._refs[key]

        return _Guard()