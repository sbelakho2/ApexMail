package apexmail

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// ── F1: send wire shape vs messages.rs SendMessageRequest ──────────────────

func TestSendEmailRequestMarshalsExactServerShape(t *testing.T) {
	t.Parallel()

	req := &SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com", Name: "Ignored Name"},
		To:      []EmailAddress{{Email: "user@example.com"}, {Email: "second@example.com", Name: "Dropped"}},
		CC:      []EmailAddress{{Email: "cc@example.com"}},
		BCC:     []EmailAddress{{Email: "bcc@example.com"}},
		Subject: "Hello!",
		HTML:    "<h1>Hello World</h1>",
		Tags:    []string{"welcome"},
		// Inputs the API rejects — must NOT be serialized:
		ReplyTo:     &EmailAddress{Email: "reply@example.com"},
		TemplateID:  "tpl_1",
		Priority:    "high",
		Attachments: []Attachment{{Filename: "a.txt", Content: "eHg="}},
		Metadata:    map[string]interface{}{"source": "go-sdk-test"},
		ScheduledAt: "2026-09-01T09:00:00Z",
	}

	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var payload map[string]any
	if err := json.Unmarshal(body, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if payload["from"] != "hello@example.com" {
		t.Fatalf("from must be a bare string, got %#v", payload["from"])
	}
	to, _ := payload["to"].([]any)
	if len(to) != 2 || to[0] != "user@example.com" || to[1] != "second@example.com" {
		t.Fatalf("to must be bare strings, got %#v", payload["to"])
	}
	if payload["scheduled_at"] != "2026-09-01T09:00:00Z" {
		t.Fatalf("scheduled_at must be snake_case, got %#v", payload["scheduled_at"])
	}

	for _, forbidden := range []string{"replyTo", "templateId", "templateData", "attachments", "priority", "scheduledAt", "name"} {
		if _, present := payload[forbidden]; present {
			t.Fatalf("field %q must not be serialized (deny_unknown_fields → 422)", forbidden)
		}
	}
}

func TestSendOverTheWireUsesExactPayload(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"m","status":"queued","created_at":"now"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Emails.Send(context.Background(), &SendEmailRequest{
		From:       EmailAddress{Email: "hello@example.com"},
		To:         []EmailAddress{{Email: "user@example.com"}},
		Subject:    "Hi",
		Text:       "Hello",
		Priority:   "high",
		TemplateID: "tpl_1",
	}); err != nil {
		t.Fatalf("send: %v", err)
	}

	for _, forbidden := range []string{"priority", "templateId", "replyTo", "scheduledAt", "attachments"} {
		if _, present := gotBody[forbidden]; present {
			t.Fatalf("field %q reached the wire", forbidden)
		}
	}
	if gotBody["from"] != "hello@example.com" {
		t.Fatalf("from must be a bare string, got %#v", gotBody["from"])
	}
}

// ── F2: webhook wire shapes vs webhooks.rs ─────────────────────────────────

func TestWebhookCreateSendsExactlyURLAndEvents(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		// Flat WebhookResponse (no envelope, secret only at creation).
		_, _ = w.Write([]byte(`{"id":"wh_1","url":"https://example.com/hook","events":["message.delivered"],"secret":"whsec_server","status":"active","created_at":"t","updated_at":"t"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	webhook, err := client.Webhooks.Create(context.Background(), &CreateWebhookRequest{
		URL:    "https://example.com/hook",
		Events: []string{"message.delivered", "*"},
		Secret: "whsec_legacy",
	})
	if err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	if len(gotBody) != 2 || gotBody["url"] != "https://example.com/hook" {
		t.Fatalf("create body must be exactly {url, events}, got %#v", gotBody)
	}
	if webhook.Secret != "whsec_server" || webhook.Status != "active" {
		t.Fatalf("flat response not parsed: %#v", webhook)
	}
}

func TestWebhookUpdateMapsActiveToStatus(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Fatalf("expected PUT, got %s", r.Method)
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = w.Write([]byte(`{"id":"wh_1","url":"https://example.com/hook","events":["message.opened"],"status":"paused","created_at":"t","updated_at":"t"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	active := false
	if _, err := client.Webhooks.Update(context.Background(), "wh_1", &UpdateWebhookRequest{
		Events: []string{"message.opened"},
		Active: &active,
	}); err != nil {
		t.Fatalf("update webhook: %v", err)
	}

	if gotBody["status"] != "paused" {
		t.Fatalf("active=false must map to status=paused, got %#v", gotBody)
	}
	for _, forbidden := range []string{"active", "secret"} {
		if _, present := gotBody[forbidden]; present {
			t.Fatalf("field %q must not be serialized", forbidden)
		}
	}
}

func TestKnownWebhookEventsMatchServerList(t *testing.T) {
	t.Parallel()

	// webhooks.rs KNOWN_WEBHOOK_EVENTS
	expected := []string{
		"email.delivered", "email.bounced", "email.complained",
		"message.sent", "message.delivered", "message.bounced",
		"message.complained", "message.opened", "message.clicked",
		"recipient.unsubscribed", "placement_test.completed",
		"bounce", "complaint", "inbound", "*",
	}
	if len(KnownWebhookEvents) != len(expected) {
		t.Fatalf("event list mismatch: %v", KnownWebhookEvents)
	}
	for i, name := range expected {
		if KnownWebhookEvents[i] != name {
			t.Fatalf("event list mismatch at %d: got %q want %q", i, KnownWebhookEvents[i], name)
		}
	}
}

// ── F4: template wire shapes vs templates.rs ───────────────────────────────

func TestTemplateCreateMarshalsExactServerShape(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(&CreateTemplateRequest{
		Name:    "welcome",
		Subject: "Welcome!",
		HTML:    "<p>Hi</p>",
		Text:    "Hi",
		Slug:    "welcome-v1",
		Engine:  "handlebars",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	if len(payload) != 4 || payload["html_body"] != "<p>Hi</p>" || payload["text_body"] != "Hi" {
		t.Fatalf("create body must be exactly {name, subject, html_body, text_body}, got %s", body)
	}
	for _, forbidden := range []string{"html", "text", "slug", "engine", "defaultData"} {
		if _, present := payload[forbidden]; present {
			t.Fatalf("field %q must not be serialized", forbidden)
		}
	}
}

func TestTemplateResponseParsesRealFlatShape(t *testing.T) {
	t.Parallel()

	// Real TemplateResponse fields, snake_case.
	body := `{"id":"tpl_1","name":"welcome","subject":"Welcome!","html_body":"<p>Hi</p>","text_body":null,"version":1,"status":"active","created_at":"t","updated_at":"t"}`
	var tpl Template
	if err := json.Unmarshal([]byte(body), &tpl); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if tpl.HTMLBody != "<p>Hi</p>" || tpl.Version != 1 || tpl.Status != "active" {
		t.Fatalf("template fields not mapped: %#v", tpl)
	}
}

// ── F5: suppression wire shapes vs suppressions.rs ─────────────────────────

func TestSuppressionSingleEmailSendsCreateSuppressionRequest(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = w.Write([]byte(`{"id":"sup_1","email":"a@example.com","reason":"bounce","source":"manual","created_at":"t"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Suppressions.Add(context.Background(), &AddSuppressionRequest{
		Emails: []string{"a@example.com"},
		Reason: "bounce",
	}); err != nil {
		t.Fatalf("add suppression: %v", err)
	}

	if gotPath != "/v1/suppressions" {
		t.Fatalf("single email must POST /v1/suppressions, got %s", gotPath)
	}
	if gotBody["email"] != "a@example.com" || gotBody["reason"] != "bounce" {
		t.Fatalf("body must be {email, reason}, got %#v", gotBody)
	}
	if _, present := gotBody["emails"]; present {
		t.Fatalf("emails[] array must never be sent (server takes a single email string)")
	}
}

func TestSuppressionMultipleEmailsUseBulkEndpoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = w.Write([]byte(`{"created":2,"duplicates":0,"invalid":0}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	resp, err := client.Suppressions.Add(context.Background(), &AddSuppressionRequest{
		Emails: []string{"a@example.com", "b@example.com"},
		Reason: "unsubscribe",
	})
	if err != nil {
		t.Fatalf("add suppressions: %v", err)
	}

	if gotPath != "/v1/suppressions/bulk" {
		t.Fatalf("multiple emails must use /v1/suppressions/bulk, got %s", gotPath)
	}
	entries, _ := gotBody["entries"].([]any)
	if len(entries) != 2 {
		t.Fatalf("bulk body must carry {entries: [{email, reason}]}, got %#v", gotBody)
	}
	if resp.Created != 2 {
		t.Fatalf("bulk response not parsed: %#v", resp)
	}
}

// ── Domain + API-key wire shapes ────────────────────────────────────────────

func TestDomainCreateSendsNameNotDomain(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &gotBody)
		_, _ = w.Write([]byte(`{"id":"dom_1","name":"mail.example.com","status":"pending","ses_verified":false,"spf_verified":false,"dkim_verified":false,"dmarc_verified":false,"return_path_verified":false,"created_at":"t"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	domain, err := client.Domains.Create(context.Background(), &CreateDomainRequest{Domain: "mail.example.com"})
	if err != nil {
		t.Fatalf("create domain: %v", err)
	}

	if len(gotBody) != 1 || gotBody["name"] != "mail.example.com" {
		t.Fatalf("body must be exactly {name}, got %#v", gotBody)
	}
	if domain.Name != "mail.example.com" || domain.Status != "pending" {
		t.Fatalf("flat DomainResponse not parsed: %#v", domain)
	}
}

func TestDomainHealthHitsGetByIdNotHealth(t *testing.T) {
	t.Parallel()

	var gotPath string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"id":"dom_1","name":"mail.example.com","status":"verified","ses_verified":true,"spf_verified":true,"dkim_verified":true,"dmarc_verified":false,"return_path_verified":false,"created_at":"t"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	domain, err := client.Domains.Health(context.Background(), "dom_1")
	if err != nil {
		t.Fatalf("domain health: %v", err)
	}
	if gotPath != "/v1/domains/dom_1" {
		t.Fatalf("Health must map to GET /v1/domains/:id (no /health endpoint), got %s", gotPath)
	}
	if !domain.DKIMVerified {
		t.Fatalf("health info not parsed from DomainResponse: %#v", domain)
	}
}

func TestAPIKeyCreateMarshalsScopesAlways(t *testing.T) {
	t.Parallel()

	body, err := json.Marshal(&CreateAPIKeyRequest{Name: "deploy"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var payload map[string]any
	_ = json.Unmarshal(body, &payload)
	if payload["scopes"] == nil {
		t.Fatalf("scopes is required by the API and must always serialize, got %s", body)
	}

	days := 30
	body, err = json.Marshal(&CreateAPIKeyRequest{Name: "deploy", Scopes: []string{"messages:send"}, ExpiresInDays: &days, ExpiresAt: "2030-01-01T00:00:00Z"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	_ = json.Unmarshal(body, &payload)
	if payload["expires_in_days"] != float64(30) {
		t.Fatalf("expires_in_days must serialize, got %s", body)
	}
	if _, present := payload["expiresAt"]; present {
		t.Fatalf("expiresAt must not be serialized, got %s", body)
	}
}

// ── F7: automatic idempotency keys on mutating POSTs ───────────────────────

func TestMutatingPostsCarryAutoIdempotencyKeyAcrossRetries(t *testing.T) {
	t.Parallel()

	var keys []string
	failures := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		keys = append(keys, r.Header.Get("X-Idempotency-Key"))
		failures++
		if failures == 1 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":{"code":"INTERNAL","message":"transient"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"wh_1","url":"https://example.com/hook","events":["message.delivered"],"status":"active","created_at":"t","updated_at":"t"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	if _, err := client.Webhooks.Create(context.Background(), &CreateWebhookRequest{
		URL:    "https://example.com/hook",
		Events: []string{"message.delivered"},
	}); err != nil {
		t.Fatalf("create webhook: %v", err)
	}

	if len(keys) != 2 {
		t.Fatalf("expected 2 attempts, got %d", len(keys))
	}
	if keys[0] == "" || keys[0] != keys[1] {
		t.Fatalf("expected the same auto idempotency key on both attempts, got %v", keys)
	}
}

// ── F9: honored Retry-After can exceed the per-request timeout ─────────────

func TestRetryAfterLargerThanRequestTimeoutStillExecutes(t *testing.T) {
	t.Parallel()

	var attempts int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts == 1 {
			// A Retry-After (1s) larger than nothing — but critically the
			// sleep must NOT be bounded by the per-request timeout context
			// (which previously wrapped the whole loop).
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMIT_EXCEEDED","message":"slow down"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"m","status":"queued","created_at":"now"}}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
		Timeout:    500 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	start := time.Now()
	resp, err := client.Emails.Send(context.Background(), &SendEmailRequest{
		From:    EmailAddress{Email: "hello@example.com"},
		To:      []EmailAddress{{Email: "user@example.com"}},
		Subject: "Hi",
		Text:    "Hello",
	})
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("send after honored Retry-After: %v", err)
	}
	if resp.ID != "m" {
		t.Fatalf("unexpected response: %#v", resp)
	}
	// The honored 1s Retry-After (plus up to ±20% jitter) must actually
	// elapse — a loop-level timeout would have canceled it.
	if elapsed < 800*time.Millisecond {
		t.Fatalf("Retry-After was not honored: elapsed %v", elapsed)
	}
}

func TestFinalRateLimitSurfacesTypedRateLimitError(t *testing.T) {
	t.Parallel()

	attempts := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"RATE_LIMIT_EXCEEDED","message":"slow down"}}`))
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
		t.Fatal("expected rate limit error")
	}
	if _, ok := err.(*RateLimitError); !ok {
		t.Fatalf("expected typed *RateLimitError, got %T: %v", err, err)
	}
	if attempts != defaultMaxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", defaultMaxRetries+1, attempts)
	}
}

// ── F11: message get parses the flat MessageDetail ─────────────────────────

func TestEmailsGetParsesFlatMessageDetail(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Real GET /v1/messages/:id payload: flat MessageDetail in the
		// ApiResponse envelope — no {"message": ...} wrapper, bare-string
		// from, snake_case created_at.
		_, _ = w.Write([]byte(`{"data":{"id":"msg_1","from":"sender@example.com","to":["user@example.com"],"subject":"Hi","status":"queued","tags":["promo"],"metadata":null,"scheduled_at":null,"sent_at":null,"created_at":"2026-08-29T00:00:00Z"},"error":null}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	detail, err := client.Emails.Get(context.Background(), "msg_1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if detail.From != "sender@example.com" || detail.CreatedAt != "2026-08-29T00:00:00Z" {
		t.Fatalf("flat MessageDetail not parsed: %#v", detail)
	}
	if len(detail.To) != 1 || detail.To[0] != "user@example.com" {
		t.Fatalf("to not parsed as string array: %#v", detail.To)
	}
}

// ── F3: platform webhook signature (ms timestamps) ─────────────────────────

func TestVerifyWebhookSignaturePlatformMillisecondVector(t *testing.T) {
	t.Parallel()

	const payload = `{"test":true}`
	const secret = "whsec_test"
	// Known vector: HMAC-SHA256("1750000000000." + payload, secret) hex.
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("1750000000000." + payload))
	if expected := hex.EncodeToString(mac.Sum(nil)); expected != "31d18ff09cab4d0547ab1c518ffc67124406e128598a7ecfa5dbcc520e4996b2" {
		t.Fatalf("vector mismatch: %s", expected)
	}

	fresh := time.Now().Add(-time.Second)
	ts := fresh.UnixMilli()
	sign := func(ts int64) string {
		mac := hmac.New(sha256.New, []byte(secret))
		_, _ = mac.Write([]byte(fmt.Sprintf("%d.%s", ts, payload)))
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}

	if !VerifyWebhookSignature(WebhookSignatureOptions{
		Payload:   []byte(payload),
		Signature: sign(ts),
		Secret:    secret,
		Timestamp: strconv.FormatInt(ts, 10),
	}) {
		t.Fatal("fresh millisecond signature must verify")
	}

	// Stale ms timestamp (1750000000000 = 2025-06-15) must fail tolerance.
	if VerifyWebhookSignature(WebhookSignatureOptions{
		Payload:   []byte(payload),
		Signature: sign(1750000000000),
		Secret:    secret,
		Timestamp: "1750000000000",
		Tolerance: 5 * time.Minute,
	}) {
		t.Fatal("stale millisecond timestamp must be rejected")
	}

	// Tampered payload.
	if VerifyWebhookSignature(WebhookSignatureOptions{
		Payload:   []byte(`{"test":false}`),
		Signature: sign(ts),
		Secret:    secret,
		Timestamp: strconv.FormatInt(ts, 10),
	}) {
		t.Fatal("tampered payload must be rejected")
	}

	// Wrong signing order ("{payload}.{ts}").
	wrong := hmac.New(sha256.New, []byte(secret))
	_, _ = wrong.Write([]byte(payload + "." + strconv.FormatInt(ts, 10)))
	if VerifyWebhookSignature(WebhookSignatureOptions{
		Payload:   []byte(payload),
		Signature: "sha256=" + hex.EncodeToString(wrong.Sum(nil)),
		Secret:    secret,
		Timestamp: strconv.FormatInt(ts, 10),
	}) {
		t.Fatal("wrong signing order must be rejected")
	}

	// sha256= header without any timestamp cannot verify.
	if VerifyWebhookSignature(WebhookSignatureOptions{
		Payload:   []byte(payload),
		Signature: sign(ts),
		Secret:    secret,
	}) {
		t.Fatal("missing timestamp must be rejected")
	}
}

// ── F8: first retry has a non-zero delay ───────────────────────────────────

func TestCalculateBackoffFirstRetryIsNonZero(t *testing.T) {
	t.Parallel()

	if got := calculateBackoff(0); got != defaultInitialBackoff {
		t.Fatalf("first retry (attempt 0) must use the base delay, got %v", got)
	}
	if got := calculateBackoff(1); got != defaultInitialBackoff {
		t.Fatalf("attempt 1 must use base delay, got %v", got)
	}
	if got := calculateBackoff(2); got != 2*time.Second {
		t.Fatalf("attempt 2 must use 0.5s*4, got %v", got)
	}
}

func TestJitteredDelayStaysWithinBounds(t *testing.T) {
	t.Parallel()

	base := 2 * time.Second
	for i := 0; i < 50; i++ {
		got := jitteredDelay(base)
		if got < 1600*time.Millisecond || got > 2400*time.Millisecond {
			t.Fatalf("jitter must stay within ±20%% of %v, got %v", base, got)
		}
	}
	if got := jitteredDelay(0); got != 0 {
		t.Fatalf("zero delay must stay zero, got %v", got)
	}
}

// ── Idempotency-key header injection strip ─────────────────────────────────

func TestIdempotencyKeyControlCharactersAreStripped(t *testing.T) {
	t.Parallel()

	var gotKey string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("X-Idempotency-Key")
		_, _ = w.Write([]byte(`{"id":"tpl_1","name":"n","subject":"s","html_body":"<p>x</p>","version":1,"status":"active","created_at":"t","updated_at":"t"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	// Caller-supplied key with CRLF injection attempt; Send passes it
	// through opts, and do() must strip control characters.
	if _, err := client.Templates.Create(context.Background(), &CreateTemplateRequest{
		Name:    "n",
		Subject: "s",
		HTML:    "<p>x</p>",
	}); err != nil {
		t.Fatalf("create template: %v", err)
	}
	if gotKey == "" {
		t.Fatal("auto idempotency key expected on template create")
	}
	if strings.ContainsAny(gotKey, "\r\n\x00") {
		t.Fatalf("control characters not stripped from idempotency key: %q", gotKey)
	}
}
