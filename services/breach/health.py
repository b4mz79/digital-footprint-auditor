import time



class HealthRegistry:


    def __init__(self):

        self.stats = {}



    def record_success(
        self,
        engine,
        elapsed,
    ):

        data = self.stats.setdefault(
            engine,
            {
                "success":0,
                "failure":0,
                "avg_time":0,
            }
        )


        data["success"] += 1


        previous = (
            data["avg_time"]
        )


        count = (
            data["success"]
        )


        data["avg_time"] = (
            (
                previous *
                (count-1)
            )
            +
            elapsed
        ) / count



    def record_failure(
        self,
        engine,
    ):

        data = self.stats.setdefault(
            engine,
            {
                "success":0,
                "failure":0,
                "avg_time":0,
            }
        )

        data["failure"] += 1



    def get(
        self,
        engine=None,
    ):

        if engine:

            return self.stats.get(
                engine,
                {},
            )


        return self.stats