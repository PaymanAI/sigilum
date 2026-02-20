"""Portable retry helper with bounded backoff for idempotent operations."""

from __future__ import annotations

import random
import time
from typing import Callable, Optional, TypeVar

T = TypeVar("T")

DEFAULT_ATTEMPTS = 3
DEFAULT_BASE_DELAY_SECONDS = 0.1
DEFAULT_MAX_DELAY_SECONDS = 2.0
DEFAULT_JITTER_RATIO = 0.2


def should_retry_http_status(status: int) -> bool:
    return status in (429, 502, 503, 504)


def _jitter_delay(delay_seconds: float, jitter_ratio: float) -> float:
    if delay_seconds <= 0 or jitter_ratio <= 0:
        return max(0.0, delay_seconds)
    window = delay_seconds * jitter_ratio
    if window <= 0:
        return max(0.0, delay_seconds)
    delta = random.uniform(-window, window)
    return max(0.0, delay_seconds + delta)


def retry_with_backoff(
    operation: Callable[[], T],
    *,
    idempotent: bool,
    attempts: int = DEFAULT_ATTEMPTS,
    base_delay_seconds: float = DEFAULT_BASE_DELAY_SECONDS,
    max_delay_seconds: float = DEFAULT_MAX_DELAY_SECONDS,
    jitter_ratio: float = DEFAULT_JITTER_RATIO,
    should_retry_result: Optional[Callable[[T], bool]] = None,
    should_retry_error: Optional[Callable[[Exception], bool]] = None,
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    if attempts < 1:
        attempts = 1
    if not idempotent and attempts > 1:
        raise ValueError("retry_with_backoff requires idempotent=True when attempts > 1")

    delay_seconds = max(0.0, base_delay_seconds)
    max_delay_seconds = max(delay_seconds, max_delay_seconds)
    jitter_ratio = max(0.0, jitter_ratio)
    should_retry_error = should_retry_error or (lambda _: False)

    for attempt in range(1, attempts + 1):
        try:
            result = operation()
            if attempt < attempts and should_retry_result is not None and should_retry_result(result):
                sleep(_jitter_delay(delay_seconds, jitter_ratio))
                delay_seconds = min(max_delay_seconds, delay_seconds * 2)
                continue
            return result
        except Exception as error:  # noqa: BLE001
            if attempt >= attempts or not should_retry_error(error):
                raise
            sleep(_jitter_delay(delay_seconds, jitter_ratio))
            delay_seconds = min(max_delay_seconds, delay_seconds * 2)

    raise RuntimeError("retry_with_backoff exhausted attempts without a terminal result")
