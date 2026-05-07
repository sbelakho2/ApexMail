package apexmail

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestDecodeAPIResponseEnvelopeMergesPaginationMeta(t *testing.T) {
	t.Parallel()

	body := []byte(`{"data":{"events":[{"id":"evt_123","messageId":"msg_123","eventType":"delivered","recipientEmail":"user@example.com","timestamp":"2026-05-05T12:00:00Z"}]},"error":null,"meta":{"pagination":{"total":1,"limit":50,"offset":0,"hasMore":false}}}`)
	var out ListEventsResponse
	if err := decodeAPIResponse(body, &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(out.Events) != 1 || out.Events[0].ID != "evt_123" {
		t.Fatalf("unexpected events: %#v", out.Events)
	}
	if out.Pagination.Total != 1 || out.Pagination.Limit != 50 || out.Pagination.HasMore {
		t.Fatalf("unexpected pagination: %#v", out.Pagination)
	}
}

func TestClientListReturnsValidationErrorFromRustEnvelope(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"data":null,"error":{"code":"VALIDATION_ERROR","message":"validation failed","details":["limit must be <= 100"]},"meta":null}`))
	}))
	defer server.Close()

	client := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	_, err := client.Events.List(context.Background(), ListEventsOptions{})
	if err == nil {
		t.Fatal("expected validation error")
	}

	var validationErr *ValidationError
	if !errors.As(err, &validationErr) {
		t.Fatalf("expected ValidationError, got %T: %v", err, err)
	}
	if validationErr.Code != "VALIDATION_ERROR" || validationErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("unexpected validation error: %#v", validationErr.APIError)
	}
	if len(validationErr.Details) != 1 || validationErr.Details[0] != "limit must be <= 100" {
		t.Fatalf("unexpected details: %#v", validationErr.Details)
	}
}

func TestClientReturnsServerAPIErrorFromRustEnvelopeAfterRetries(t *testing.T) {
	t.Parallel()

	var attempts int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"data":null,"error":{"code":"INTERNAL_ERROR","message":"internal server error"},"meta":null}`))
	}))
	defer server.Close()

	client := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	_, err := client.Emails.Get(context.Background(), "msg_123")
	if err == nil {
		t.Fatal("expected API error")
	}

	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %T: %v", err, err)
	}
	if apiErr.Code != "INTERNAL_ERROR" || apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("unexpected API error: %#v", apiErr)
	}
	if got := atomic.LoadInt32(&attempts); got != defaultMaxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", defaultMaxRetries+1, got)
	}
}
