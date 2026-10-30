"""A small in-process sliding-window limiter for endpoints that have no login to hang a quota on.

It is per worker process, which is enough to stop one machine hammering a form; it is not a
substitute for rate limiting at the reverse proxy."""
import threading
import time
from collections import defaultdict, deque


class SlidingWindowLimiter:
    def __init__(self, max_calls: int, per_seconds: float, max_keys: int = 10_000):
        self.max_calls = max_calls
        self.per_seconds = per_seconds
        self.max_keys = max_keys
        self._hits = defaultdict(deque)
        self._lock = threading.Lock()

    def allow(self, key: str, now: float = None) -> bool:
        now = time.monotonic() if now is None else now
        with self._lock:
            if len(self._hits) > self.max_keys:  # forget idle keys rather than grow without bound
                for k in [k for k, q in self._hits.items() if not q or now - q[-1] > self.per_seconds]:
                    del self._hits[k]
            q = self._hits[key]
            while q and now - q[0] > self.per_seconds:
                q.popleft()
            if len(q) >= self.max_calls:
                return False
            q.append(now)
            return True

    def is_limited(self, key: str, now: float = None) -> bool:
        """Whether the key has used up its quota, without counting this look as a use."""
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._hits.get(key)
            if not q:
                return False
            while q and now - q[0] > self.per_seconds:
                q.popleft()
            return len(q) >= self.max_calls

    def record(self, key: str, now: float = None) -> None:
        """Counts a use (for limits that apply to failures only)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            self._hits[key].append(now)

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()
