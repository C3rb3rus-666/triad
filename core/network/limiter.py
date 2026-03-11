import random

# simple logistic map chaos generator
_last_x = random.random()


def next_interval(base: float = 1.0) -> float:
    """Return next sleep interval using logistic chaos plus small noise.

    Interval = base + (noise * 0.45), where noise evolves by logistic map.
    """
    global _last_x
    # logistic map parameter for chaotic behaviour
    r = 3.99
    _last_x = r * _last_x * (1 - _last_x)
    noise = _last_x
    return base + (noise * 0.45)
