package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"sigilum.local/gateway/internal/connectors"
)

var errRequestBodyTooLarge = errors.New("request body exceeds configured limit")

type statusRecorder struct {
	http.ResponseWriter
	status       int
	bytesWritten int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(payload []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(payload)
	r.bytesWritten += n
	return n, err
}

func writeConnectionError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, connectors.ErrConnectionNotFound):
		status = http.StatusNotFound
	case errors.Is(err, connectors.ErrConnectionExists):
		status = http.StatusConflict
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func writeCredentialVariableError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, connectors.ErrCredentialVariableNotFound):
		status = http.StatusNotFound
	}
	writeJSON(w, status, errorResponse{Error: err.Error()})
}

func readLimitedRequestBody(r *http.Request, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 2 << 20
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, errors.New("failed to read request body")
	}
	if int64(len(body)) > maxBytes {
		return nil, errRequestBodyTooLarge
	}
	return body, nil
}

func writeRequestBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestBodyTooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{
			Error: "request body exceeds configured limit",
			Code:  "REQUEST_BODY_TOO_LARGE",
		})
		return
	}
	writeJSON(w, http.StatusBadRequest, errorResponse{Error: "failed to read request body"})
}

func readJSONBody(r *http.Request, out any, maxBytes int64) error {
	body, err := readLimitedRequestBody(r, maxBytes)
	if err != nil {
		return err
	}
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("request body is required")
	}
	if err := json.Unmarshal(body, out); err != nil {
		return fmt.Errorf("invalid JSON body: %w", err)
	}
	return nil
}

func writeJSONBodyError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRequestBodyTooLarge) {
		writeJSON(w, http.StatusRequestEntityTooLarge, errorResponse{
			Error: "request body exceeds configured limit",
			Code:  "REQUEST_BODY_TOO_LARGE",
		})
		return
	}
	writeJSON(w, http.StatusBadRequest, errorResponse{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func setCORSHeaders(w http.ResponseWriter, r *http.Request, allowedOrigins map[string]struct{}) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	if origin != "" {
		w.Header().Set("Vary", "Origin")
		if _, ok := allowedOrigins[origin]; ok {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")
		}
	}
}

func writeProxyAuthFailure(w http.ResponseWriter) {
	writeJSON(w, http.StatusForbidden, errorResponse{
		Error: "request not authorized",
		Code:  "AUTH_FORBIDDEN",
	})
}
