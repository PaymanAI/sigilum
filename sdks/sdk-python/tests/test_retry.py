from __future__ import annotations

import pytest

from sigilum.retry import retry_with_backoff, should_retry_http_status


def test_retry_with_backoff_retries_retryable_errors() -> None:
    attempts = {"count": 0}

    def operation() -> str:
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("temporary")
        return "ok"

    result = retry_with_backoff(
        operation,
        idempotent=True,
        attempts=3,
        sleep=lambda _: None,
        should_retry_error=lambda _: True,
    )
    assert result == "ok"
    assert attempts["count"] == 3


def test_retry_with_backoff_requires_idempotent_for_multiple_attempts() -> None:
    with pytest.raises(ValueError):
        retry_with_backoff(
            lambda: "ok",
            idempotent=False,
            attempts=2,
        )


def test_retry_with_backoff_retries_retryable_http_results() -> None:
    attempts = {"count": 0}

    def operation() -> dict[str, int]:
        attempts["count"] += 1
        if attempts["count"] < 2:
            return {"status": 503}
        return {"status": 200}

    result = retry_with_backoff(
        operation,
        idempotent=True,
        attempts=3,
        sleep=lambda _: None,
        should_retry_result=lambda value: should_retry_http_status(value["status"]),
    )
    assert result["status"] == 200
    assert attempts["count"] == 2


def test_should_retry_http_status() -> None:
    assert should_retry_http_status(429) is True
    assert should_retry_http_status(502) is True
    assert should_retry_http_status(503) is True
    assert should_retry_http_status(504) is True
    assert should_retry_http_status(400) is False
