from services.breach.limiter import (
    TokenBucket,
)



def test_token_bucket():

    limiter = TokenBucket(
        rate=0,
        capacity=1,
    )


    assert limiter.consume()


    assert not limiter.consume()