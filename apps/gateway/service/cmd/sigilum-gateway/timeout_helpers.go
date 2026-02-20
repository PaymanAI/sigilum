package main

import (
	"context"
	"net/http"
	"time"
)

func withRequestTimeout(timeout time.Duration, next http.HandlerFunc) http.HandlerFunc {
	if timeout <= 0 {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), timeout)
		defer cancel()
		next(w, r.WithContext(ctx))
	}
}
