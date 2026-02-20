package main

import "net/http"

func withInFlightRequestTracking(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gatewayMetricRegistry.recordRequestStart()
		defer gatewayMetricRegistry.recordRequestFinish()
		next.ServeHTTP(w, r)
	})
}
