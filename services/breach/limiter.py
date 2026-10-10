import time

class TokenBucket:
    def __init__(self, rate: float = 1, capacity: int = 2):
        self.rate = rate
        self.capacity = capacity
        self.tokens = capacity
        self.timestamp = time.monotonic()

    def consume(self, amount: int = 1) -> bool:
        now = time.monotonic()
        elapsed = (now - self.timestamp)
        self.timestamp = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
        if self.tokens >= amount:
            self.tokens -= amount
            return True
        return False

class LimiterRegistry:
    def __init__(self):
        self._limiters = {}

    def _get(self, engine: str):
        if engine not in self._limiters:
            self._limiters[engine] = (TokenBucket(rate=0.2, capacity=2))
        return self._limiters[engine]

    def allow(self, engine: str):
        return (
            self
            ._get(engine)
            .consume()
        )

    def penalize(self, engine: str):
        limiter = self._get(engine)
        limiter.tokens = 0
