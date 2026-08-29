package apexmail

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// ── SDK-C: real API response shapes ────────────────────────────────────────

func TestEmailsSendDecodesRealFlatResponse(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Real single-send payload (api-server ApiResponse envelope wrapping
		// MessageResponse {id, status, created_at}).
		_, _ = w.Write([]byte(`{"data":{"id":"msg_flat_1","status":"queued","created_at":"2026-08-21T12:00:00Z"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp, err := client.Emails.Send(context.Background(), &SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com"},
		To:      []EmailAddress{{Email: "user@example.com"}},
		Subject: "Hi",
		Text:    "Hello",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.ID != "msg_flat_1" {
		t.Fatalf("expected flat ID populated, got %#v", resp)
	}
	if resp.Status != "queued" {
		t.Fatalf("expected status populated, got %#v", resp)
	}
	if resp.CreatedAt != "2026-08-21T12:00:00Z" {
		t.Fatalf("expected created_at populated, got %#v", resp)
	}
}

func TestEmailsBatchDecodesRealResponseShape(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Real batch payload: {accepted, rejected, results:[{index, id?, status, error?}]}
		_, _ = w.Write([]byte(`{"data":{"accepted":2,"rejected":1,"results":[` +
			`{"index":0,"id":"msg_b1","status":"queued"},` +
			`{"index":1,"id":"msg_b2","status":"queued"},` +
			`{"index":2,"status":"rejected","error":"invalid recipient"}]}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp, err := client.Emails.Batch(context.Background(), &BatchSendRequest{Messages: []*SendEmailRequest{
		{From: EmailAddress{Email: "a@example.com"}, To: []EmailAddress{{Email: "x@example.com"}}, Subject: "1", Text: "x"},
		{From: EmailAddress{Email: "a@example.com"}, To: []EmailAddress{{Email: "y@example.com"}}, Subject: "2", Text: "x"},
		{From: EmailAddress{Email: "a@example.com"}, To: []EmailAddress{{Email: "z@example.com"}}, Subject: "3", Text: "x"},
	}})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if resp.Accepted != 2 || resp.Rejected != 1 {
		t.Fatalf("expected accepted=2 rejected=1, got %#v", resp)
	}
	if len(resp.Results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(resp.Results))
	}
	if resp.Results[0].ID != "msg_b1" || resp.Results[0].Status != "queued" {
		t.Fatalf("accepted item not mapped: %#v", resp.Results[0])
	}
	if resp.Results[2].ID != "" || resp.Results[2].Status != "rejected" || resp.Results[2].Error != "invalid recipient" {
		t.Fatalf("rejected item not mapped: %#v", resp.Results[2])
	}
}

// ── SDK-B: automatic idempotency keys ──────────────────────────────────────

func TestEmailsSendReplaysSameAutoIdempotencyKeyAcrossRetries(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var keys []string
	failures := 0

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get("X-Idempotency-Key"))
		failures++
		fail := failures == 1
		mu.Unlock()

		if fail {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"INTERNAL","message":"transient"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"msg_retry","status":"queued","created_at":"2026-08-21T12:00:00Z"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp, err := client.Emails.Send(context.Background(), &SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com"},
		To:      []EmailAddress{{Email: "user@example.com"}},
		Subject: "Hi",
		Text:    "Hello",
	})
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	if resp.ID != "msg_retry" {
		t.Fatalf("expected retried send to succeed, got %#v", resp)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(keys))
	}
	if keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("expected same non-empty auto idempotency key on both attempts, got %v", keys)
	}
}

func TestEmailsSendGeneratesDifferentKeysPerLogicalSend(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var keys []string

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		keys = append(keys, r.Header.Get("X-Idempotency-Key"))
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"m","status":"queued","created_at":"now"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	for i := 0; i < 2; i++ {
		if _, err := client.Emails.Send(context.Background(), &SendEmailRequest{
			From:    EmailAddress{Email: "hello@example.com"},
			To:      []EmailAddress{{Email: "user@example.com"}},
			Subject: "Hi",
			Text:    "Hello",
		}); err != nil {
			t.Fatalf("send %d: %v", i, err)
		}
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 sends, got %d", len(keys))
	}
	if keys[0] == "" || keys[1] == "" || keys[0] == keys[1] {
		t.Fatalf("expected different auto keys per logical send, got %v", keys)
	}
}

func TestEmailsSendHonorsCallerIdempotencyKey(t *testing.T) {
	t.Parallel()

	var gotKey string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"m","status":"queued","created_at":"now"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Emails.Send(context.Background(), &SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com"},
		To:      []EmailAddress{{Email: "user@example.com"}},
		Subject: "Hi",
		Text:    "Hello",
	}, SendOptions{IdempotencyKey: "caller-key"}); err != nil {
		t.Fatalf("send: %v", err)
	}
	if gotKey != "caller-key" {
		t.Fatalf("expected caller key to win, got %q", gotKey)
	}
}

func TestEmailsBatchSendsIdempotencyKey(t *testing.T) {
	t.Parallel()

	var gotKey string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Idempotency-Key")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"accepted":1,"rejected":0,"results":[{"index":0,"id":"m","status":"queued"}]}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Emails.Batch(context.Background(), &BatchSendRequest{Messages: []*SendEmailRequest{
		{From: EmailAddress{Email: "a@example.com"}, To: []EmailAddress{{Email: "x@example.com"}}, Subject: "1", Text: "x"},
	}}); err != nil {
		t.Fatalf("batch: %v", err)
	}
	if gotKey == "" {
		t.Fatal("expected batch call to carry an auto idempotency key")
	}
}

// Retries must happen only for retryable statuses: a 422 must fail fast with
// a single request.
func TestEmailsSendDoesNotRetryClientError(t *testing.T) {
	t.Parallel()

	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":{"code":"VALIDATION_ERROR","message":"nope"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	_, err = client.Emails.Send(context.Background(), &SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com"},
		To:      []EmailAddress{{Email: "user@example.com"}},
		Subject: "Hi",
		Text:    "Hello",
	})
	if err == nil {
		t.Fatal("expected error for 422")
	}
	if requests != 1 {
		t.Fatalf("expected exactly 1 request for non-retryable status, got %d", requests)
	}
}

// ── SDK-F: Retry-After honored up to 120s ──────────────────────────────────

func TestRetryDelayHonorsRetryAfterInFull(t *testing.T) {
	t.Parallel()

	resp := func(header string) *http.Response {
		r := &http.Response{Header: http.Header{}}
		if header != "" {
			r.Header.Set("Retry-After", header)
		}
		return r
	}

	if got := retryDelay(resp("60"), 0); got != 60*time.Second {
		t.Fatalf("Retry-After 60: expected 60s, got %v", got)
	}
	if got := retryDelay(resp("3"), 2); got != 3*time.Second {
		t.Fatalf("Retry-After 3 beats backoff 2s: expected 3s, got %v", got)
	}
	if got := retryDelay(resp("300"), 0); got != maxRetryAfterDelay {
		t.Fatalf("Retry-After 300: expected cap 120s, got %v", got)
	}
	if got := retryDelay(resp(""), 2); got != 2*time.Second {
		t.Fatalf("no Retry-After: expected quadratic backoff 2s, got %v", got)
	}
	// F8: the first retry uses attempt 1, so the backoff floor is 500ms —
	// a 0-based exponent produced a 0s delay (an immediate hammer at a
	// server that had just said "slow down").
	if got := retryDelay(resp(""), 0); got != 500*time.Millisecond {
		t.Fatalf("no Retry-After, first retry: expected backoff floor 500ms, got %v", got)
	}
	if got := retryDelay(resp("garbage"), 0); got != 500*time.Millisecond {
		t.Fatalf("garbage Retry-After: expected backoff floor 500ms, got %v", got)
	}
}

// ── SDK-G L5: display-name strings are not valid bare addresses ────────────

func TestIsValidEmailAddressRejectsDisplayNameForms(t *testing.T) {
	t.Parallel()

	for _, valid := range []string{"a@b.co", "user.name+tag@sub.example.org"} {
		if !isValidEmailAddress(valid) {
			t.Fatalf("expected %q to be valid", valid)
		}
	}
	for _, invalid := range []string{
		"Display Name <a@b.co>",
		"a@b.co, c@d.co",
		"<a@b.co>",
		"not-an-email",
		"",
		"local@",
		"@domain.com",
	} {
		if isValidEmailAddress(invalid) {
			t.Fatalf("expected %q to be rejected", invalid)
		}
	}
}

func TestValidateSendEmailRequestRejectsDisplayNameFrom(t *testing.T) {
	t.Parallel()

	err := validateSendEmailRequest(&SendEmailRequest{
		From:    EmailAddress{Email: "Display Name <a@b.co>"},
		To:      []EmailAddress{{Email: "x@y.co"}},
		Subject: "Hi",
		Text:    "x",
	})
	if err == nil {
		t.Fatal("expected display-name email string to be rejected")
	}
}

// ── Non-happy-path: non-JSON 502 body surfaces as an error, not success ────

func TestEmailsSendNonJSON502ReturnsError(t *testing.T) {
	t.Parallel()

	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html><body>502 Bad Gateway</body></html>"))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client(), Timeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	resp, err := client.Emails.Send(context.Background(), &SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com"},
		To:      []EmailAddress{{Email: "user@example.com"}},
		Subject: "Hi",
		Text:    "Hello",
	})
	if err == nil {
		t.Fatalf("expected error for non-JSON 502, got %#v", resp)
	}
	apiErr, ok := err.(*APIError)
	if !ok {
		t.Fatalf("expected *APIError, got %T: %v", err, err)
	}
	if apiErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected status 502 preserved, got %d", apiErr.StatusCode)
	}
	if requests != defaultMaxRetries+1 {
		t.Fatalf("expected %d attempts (retries on 5xx), got %d", defaultMaxRetries+1, requests)
	}
}

// ── Response-size cap is enforced while streaming ─────────────────────────

func TestEmailsResponseTooLargeIsRejected(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		chunk := make([]byte, 1024)
		for i := range chunk {
			chunk[i] = 'x'
		}
		for i := 0; i < 64; i++ { // 64 KiB total
			_, _ = w.Write(chunk)
		}
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{
		BaseURL:          server.URL,
		HTTPClient:       server.Client(),
		MaxResponseBytes: 16 * 1024,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	_, err = client.Emails.Get(context.Background(), "msg_123")
	if err == nil {
		t.Fatal("expected response-too-large error")
	}
}
