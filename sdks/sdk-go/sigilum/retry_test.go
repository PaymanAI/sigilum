package sigilum

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestRetryWithBackoffRetriesRetryableErrors(t *testing.T) {
	attempts := 0
	result, err := RetryWithBackoff(
		context.Background(),
		func(ctx context.Context) (string, error) {
			attempts++
			if attempts < 3 {
				return "", errors.New("temporary")
			}
			return "ok", nil
		},
		func(_ string, err error) bool {
			return err != nil
		},
		RetryOptions{
			Idempotent: true,
			Attempts:   3,
			Sleep:      func(context.Context, time.Duration) error { return nil },
		},
	)
	if err != nil {
		t.Fatalf("expected retry success, got error: %v", err)
	}
	if result != "ok" {
		t.Fatalf("expected result ok, got %q", result)
	}
	if attempts != 3 {
		t.Fatalf("expected 3 attempts, got %d", attempts)
	}
}

func TestRetryWithBackoffRequiresIdempotentForMultipleAttempts(t *testing.T) {
	_, err := RetryWithBackoff(
		context.Background(),
		func(ctx context.Context) (string, error) {
			return "ok", nil
		},
		nil,
		RetryOptions{
			Idempotent: false,
			Attempts:   2,
		},
	)
	if err == nil {
		t.Fatal("expected idempotent validation error")
	}
}

func TestRetryWithBackoffRetriesRetryableStatuses(t *testing.T) {
	type result struct {
		Status int
	}
	attempts := 0
	value, err := RetryWithBackoff(
		context.Background(),
		func(ctx context.Context) (result, error) {
			attempts++
			if attempts < 2 {
				return result{Status: 503}, nil
			}
			return result{Status: 200}, nil
		},
		func(res result, err error) bool {
			return err == nil && ShouldRetryHTTPStatus(res.Status)
		},
		RetryOptions{
			Idempotent: true,
			Attempts:   3,
			Sleep:      func(context.Context, time.Duration) error { return nil },
		},
	)
	if err != nil {
		t.Fatalf("expected retry success, got error: %v", err)
	}
	if value.Status != 200 {
		t.Fatalf("expected final status 200, got %d", value.Status)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts, got %d", attempts)
	}
}

func TestShouldRetryHTTPStatus(t *testing.T) {
	if !ShouldRetryHTTPStatus(429) {
		t.Fatal("expected 429 to be retryable")
	}
	if !ShouldRetryHTTPStatus(502) {
		t.Fatal("expected 502 to be retryable")
	}
	if !ShouldRetryHTTPStatus(503) {
		t.Fatal("expected 503 to be retryable")
	}
	if !ShouldRetryHTTPStatus(504) {
		t.Fatal("expected 504 to be retryable")
	}
	if ShouldRetryHTTPStatus(400) {
		t.Fatal("expected 400 to be non-retryable")
	}
}
