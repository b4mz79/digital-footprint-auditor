import time

from services.breach.circuit_breaker import (
    CircuitBreaker,
)



def test_circuit_opens_after_failures():

    cb = CircuitBreaker(
        failure_threshold=2,
        recovery_seconds=1,
    )


    assert cb.allow()


    cb.failure()
    cb.failure()


    assert not cb.allow()



def test_circuit_recovers():

    cb = CircuitBreaker(
        failure_threshold=1,
        recovery_seconds=0,
    )


    cb.failure()


    assert cb.allow()