import time
import logging


logger = logging.getLogger(
    "BreachScanner"
)



class CircuitState:

    CLOSED = "closed"

    OPEN = "open"

    HALF_OPEN = "half_open"



class CircuitBreaker:


    def __init__(
        self,
        failure_threshold: int = 3,
        recovery_seconds: int = 60,
    ):

        self.failure_threshold = (
            failure_threshold
        )

        self.recovery_seconds = (
            recovery_seconds
        )

        self.failures = 0

        self.state = (
            CircuitState.CLOSED
        )

        self.opened_at = 0



    def allow(self) -> bool:


        if self.state == CircuitState.CLOSED:
            return True


        if self.state == CircuitState.OPEN:

            elapsed = (
                time.monotonic()
                -
                self.opened_at
            )

            if elapsed >= self.recovery_seconds:

                self.state = (
                    CircuitState.HALF_OPEN
                )

                return True


            return False


        return True



    def success(self):

        self.failures = 0

        self.state = (
            CircuitState.CLOSED
        )



    def failure(self):

        self.failures += 1


        if self.failures >= self.failure_threshold:

            self.state = (
                CircuitState.OPEN
            )

            self.opened_at = (
                time.monotonic()
            )


            logger.warning(
                "Circuit opened after %s failures",
                self.failures,
            )





class CircuitRegistry:


    def __init__(self):

        self._items = {}



    def _get(
        self,
        name: str,
    ) -> CircuitBreaker:

        if name not in self._items:

            self._items[name] = (
                CircuitBreaker()
            )

        return self._items[name]



    def allow(
        self,
        name: str,
    ) -> bool:

        return self._get(name).allow()



    def record_success(
        self,
        name: str,
    ):

        self._get(name).success()



    def record_failure(
        self,
        name: str,
    ):

        self._get(name).failure()