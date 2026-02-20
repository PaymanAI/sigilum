package sigilum

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net/http"
	"time"
)

const (
	defaultRetryAttempts = 3
	defaultRetryJitter   = 0.2
)

type RetryOptions struct {
	Attempts   int
	BaseDelay  time.Duration
	MaxDelay   time.Duration
	Jitter     float64
	Idempotent bool
	Sleep      func(ctx context.Context, delay time.Duration) error
}

func ShouldRetryHTTPStatus(status int) bool {
	return status == http.StatusTooManyRequests ||
		status == http.StatusBadGateway ||
		status == http.StatusServiceUnavailable ||
		status == http.StatusGatewayTimeout
}

func RetryWithBackoff[T any](
	ctx context.Context,
	operation func(ctx context.Context) (T, error),
	shouldRetry func(result T, err error) bool,
	options RetryOptions,
) (T, error) {
	var zero T
	if operation == nil {
		return zero, errors.New("operation is required")
	}

	attempts := options.Attempts
	if attempts < 1 {
		attempts = defaultRetryAttempts
	}
	if !options.Idempotent && attempts > 1 {
		return zero, errors.New("RetryWithBackoff requires Idempotent=true when attempts > 1")
	}
	if shouldRetry == nil {
		shouldRetry = func(_ T, _ error) bool { return false }
	}

	baseDelay := options.BaseDelay
	if baseDelay < 0 {
		baseDelay = 0
	}
	maxDelay := options.MaxDelay
	if maxDelay < baseDelay {
		maxDelay = baseDelay
	}
	jitter := options.Jitter
	if jitter <= 0 {
		jitter = defaultRetryJitter
	}
	sleep := options.Sleep
	if sleep == nil {
		sleep = sleepWithContextDuration
	}

	delay := baseDelay
	var lastResult T
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		if ctx != nil && ctx.Err() != nil {
			return zero, ctx.Err()
		}
		result, err := operation(ctx)
		lastResult = result
		lastErr = err

		if attempt >= attempts || !shouldRetry(result, err) {
			return result, err
		}

		if err := sleep(ctx, jitterDuration(delay, jitter)); err != nil {
			return zero, fmt.Errorf("retry sleep interrupted: %w", err)
		}
		if delay > 0 {
			delay = delay * 2
			if delay > maxDelay {
				delay = maxDelay
			}
		}
	}
	return lastResult, lastErr
}

func jitterDuration(base time.Duration, jitter float64) time.Duration {
	if base <= 0 || jitter <= 0 {
		return base
	}
	window := int64(float64(base) * jitter)
	if window <= 0 {
		return base
	}
	delta := rand.Int63n((2 * window) + 1)
	adjustment := time.Duration(delta - window)
	if base+adjustment <= 0 {
		return base
	}
	return base + adjustment
}

func sleepWithContextDuration(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		return nil
	}
	if ctx == nil {
		time.Sleep(delay)
		return nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
