package apexmail

// Shape-contract tests: every fixture in this file is the EXACT serialization
// the corresponding Rust handler produces (line-cited in the test comments).
// A fixture here may never encode a payload no route produces (GO-12).

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// newTestServer creates an httptest TLS server around handler; the returned
// client trusts the server's certificate.
func newTestServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *Client) {
	t.Helper()
	server := httptest.NewTLSServer(handler)
	t.Cleanup(server.Close)
	client, err := New("am_live_1234567890abcdef", Config{BaseURL: server.URL, HTTPClient: server.Client()})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}
	return server, client
}

// ── GO-2: Events.List / GetByMessage (bare array, snake_case) ───────────────

func TestEventsListDecodesRealBareArrayAndSendsAcceptedFilters(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		if r.URL.Path != "/v1/events" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		// routes/events.rs list_events → Json<Vec<EventResponse>> — a BARE
		// array of {id, message_id, event_type, recipient, metadata, timestamp}.
		_, _ = w.Write([]byte(`[{"id":"evt_1","message_id":"msg_1","event_type":"delivered","recipient":"user@example.com","metadata":{"smtp":"250 ok"},"timestamp":"2026-10-06T12:00:00Z"}]`))
	})

	limit := 10
	resp, err := client.Events.List(context.Background(), ListEventsOptions{
		EventType: "delivered",
		MessageID: "msg_1",
		Limit:     &limit,
		Offset:    5,
	})
	if err != nil {
		t.Fatalf("events list: %v", err)
	}
	if len(resp.Events) != 1 {
		t.Fatalf("bare array not decoded: %#v", resp.Events)
	}
	event := resp.Events[0]
	if event.ID != "evt_1" || event.MessageID != "msg_1" || event.EventType != "delivered" || event.Recipient != "user@example.com" {
		t.Fatalf("snake_case fields not mapped: %#v", event)
	}
	if event.Timestamp != "2026-10-06T12:00:00Z" {
		t.Fatalf("timestamp not mapped: %#v", event)
	}
	// The server's ListEventsQuery is deny_unknown_fields {limit, offset,
	// event_type, message_id} — the query must carry exactly those names.
	want := url.Values{"limit": {"10"}, "offset": {"5"}, "event_type": {"delivered"}, "message_id": {"msg_1"}}
	if gotQuery.Encode() != want.Encode() {
		t.Fatalf("query mismatch:\n got %s\nwant %s", gotQuery.Encode(), want.Encode())
	}
}

func TestEventsGetByMessageUsesMessageIDParam(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte(`[]`))
	})
	if _, err := client.Events.GetByMessage(context.Background(), "msg_42"); err != nil {
		t.Fatalf("get by message: %v", err)
	}
	if gotQuery.Get("message_id") != "msg_42" {
		t.Fatalf("message_id must be the snake_case query param, got %q", gotQuery.Encode())
	}
	if gotQuery.Get("messageId") != "" {
		t.Fatalf("camelCase messageId must not be sent: %s", gotQuery.Encode())
	}
}

// ── GO-5: Events.Get (flat object, no wrapper) ──────────────────────────────

func TestEventsGetDecodesFlatRealEvent(t *testing.T) {
	t.Parallel()

	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/events/evt_9" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		// routes/events.rs get_event → Json(row.into()) — flat EventResponse.
		_, _ = w.Write([]byte(`{"id":"evt_9","message_id":"msg_7","event_type":"bounced","recipient":"bob@example.com","metadata":null,"timestamp":"2026-10-06T13:00:00Z"}`))
	})

	event, err := client.Events.Get(context.Background(), "evt_9")
	if err != nil {
		t.Fatalf("event get: %v", err)
	}
	if event.ID != "evt_9" || event.MessageID != "msg_7" || event.EventType != "bounced" || event.Recipient != "bob@example.com" {
		t.Fatalf("flat event not decoded field-for-field: %#v", event)
	}
	if string(event.Metadata) != "null" {
		t.Fatalf("metadata must be captured: %s", event.Metadata)
	}
}

// ── GO-3: Analytics.Volume / Events.Timeseries (arrays) ─────────────────────

func TestAnalyticsVolumeDecodesArrayInsideEnvelope(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/analytics/volume" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		gotQuery = r.URL.Query()
		// routes/analytics.rs volume → Json<ApiResponse<Vec<VolumePoint>>>.
		_, _ = w.Write([]byte(`{"data":[{"date":"2026-10-01T00:00:00Z","sent":10,"delivered":9,"bounced":1},{"date":"2026-10-02T00:00:00Z","sent":12,"delivered":11,"bounced":1}],"error":null}`))
	})

	points, err := client.Analytics.Volume(context.Background(), AnalyticsOptions{From: "2026-10-01", To: "2026-10-02", Interval: "day"})
	if err != nil {
		t.Fatalf("analytics volume: %v", err)
	}
	if len(points) != 2 || points[0].Sent != 10 || points[1].Delivered != 11 || points[0].Bounced != 1 {
		t.Fatalf("VolumePoint array not decoded: %#v", points)
	}
	if gotQuery.Get("interval") != "day" {
		t.Fatalf("unexpected query: %s", gotQuery.Encode())
	}
}

func TestEventsTimeseriesDecodesBareArrayAndStatsIsObject(t *testing.T) {
	t.Parallel()

	requests := 0
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/v1/events/timeseries":
			// routes/events.rs event_timeseries → Json<Vec<TimeseriesPoint>>.
			_, _ = w.Write([]byte(`[{"timestamp":"2026-10-06T00:00:00Z","count":42,"event_type":"delivered"}]`))
		case "/v1/events/stats":
			// event_stats → Json<EventStats> object.
			_, _ = w.Write([]byte(`{"total":100,"delivered":95,"bounced":3,"complained":1,"opened":40,"clicked":10}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	points, err := client.Events.Timeseries(context.Background(), EventAggregateOptions{From: "2026-10-01T00:00:00Z", To: "2026-10-07T00:00:00Z"})
	if err != nil {
		t.Fatalf("timeseries: %v", err)
	}
	if len(points) != 1 || points[0].Count != 42 || points[0].EventType != "delivered" || points[0].Timestamp != "2026-10-06T00:00:00Z" {
		t.Fatalf("TimeseriesPoint array not decoded: %#v", points)
	}

	stats, err := client.Events.Stats(context.Background(), EventAggregateOptions{From: "2026-10-01T00:00:00Z", To: "2026-10-07T00:00:00Z"})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats["total"] != float64(100) || stats["bounced"] != float64(3) {
		t.Fatalf("EventStats object not decoded: %#v", stats)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
}

func TestEventsStatsSendsOnlyFromAndTo(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query()
		_, _ = w.Write([]byte(`{"total":0}`))
	})
	if _, err := client.Events.Stats(context.Background(), EventAggregateOptions{From: "2026-10-01T00:00:00Z", To: "2026-10-02T00:00:00Z"}); err != nil {
		t.Fatalf("stats: %v", err)
	}
	want := url.Values{"from": {"2026-10-01T00:00:00Z"}, "to": {"2026-10-02T00:00:00Z"}}
	if gotQuery.Encode() != want.Encode() {
		t.Fatalf("StatsQuery is deny_unknown_fields {from, to}:\n got %s\nwant %s", gotQuery.Encode(), want.Encode())
	}
}

// ── GO-4: APIKeys.List (bare array) + cursor rejection ──────────────────────

func TestAPIKeysListDecodesBareArray(t *testing.T) {
	t.Parallel()

	var gotQuery url.Values
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/auth/api-keys" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		gotQuery = r.URL.Query()
		// routes/auth.rs list_api_keys → Json<Vec<ApiKeyInfo>> (bare array),
		// ApiKeyInfo = {id, name, key_prefix, scopes, last_used_at, created_at,
		// expires_at}.
		_, _ = w.Write([]byte(`[{"id":"cda60ad6-cd56-435a-84bf-29688580b47e","name":"deploy","key_prefix":"am_live_…0w8K","scopes":["*"],"last_used_at":null,"created_at":"2026-10-07T10:36:10Z","expires_at":"2027-01-05T10:36:10Z"}]`))
	})

	keys, err := client.APIKeys.List(context.Background(), ListAPIKeysOptions{Limit: 25, Offset: 10})
	if err != nil {
		t.Fatalf("api keys list: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("bare array not decoded: %#v", keys)
	}
	key := keys[0]
	if key.ID != "cda60ad6-cd56-435a-84bf-29688580b47e" || key.Name != "deploy" || key.KeyPrefix != "am_live_…0w8K" {
		t.Fatalf("ApiKeyInfo fields not mapped: %#v", key)
	}
	if len(key.Scopes) != 1 || key.Scopes[0] != "*" {
		t.Fatalf("scopes not mapped: %#v", key.Scopes)
	}
	if key.CreatedAt != "2026-10-07T10:36:10Z" || key.ExpiresAt != "2027-01-05T10:36:10Z" {
		t.Fatalf("timestamps not mapped: %#v", key)
	}
	want := url.Values{"limit": {"25"}, "offset": {"10"}}
	if gotQuery.Encode() != want.Encode() {
		t.Fatalf("ListApiKeysQuery is deny_unknown_fields {limit, offset}:\n got %s\nwant %s", gotQuery.Encode(), want.Encode())
	}
}

// ── GO-8: cursor is rejected client-side on the four deny_unknown_fields routes ──

func TestCursorRejectedClientSideWhereServerRejectsIt(t *testing.T) {
	t.Parallel()

	var requests int
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		_, _ = w.Write([]byte(`[]`))
	})

	cases := []struct {
		name string
		call func() error
	}{
		{"templates", func() error {
			_, err := client.Templates.List(context.Background(), ListTemplatesOptions{Cursor: "abc"})
			return err
		}},
		{"suppressions", func() error {
			_, err := client.Suppressions.List(context.Background(), ListSuppressionsOptions{Cursor: "abc"})
			return err
		}},
		{"events", func() error {
			_, err := client.Events.List(context.Background(), ListEventsOptions{Cursor: "abc"})
			return err
		}},
		{"api keys", func() error {
			_, err := client.APIKeys.List(context.Background(), ListAPIKeysOptions{Cursor: "abc"})
			return err
		}},
	}
	for _, tc := range cases {
		err := tc.call()
		if err == nil {
			t.Fatalf("%s: cursor must be rejected client-side (server query is deny_unknown_fields without it)", tc.name)
		}
		if !strings.Contains(err.Error(), "cursor") {
			t.Fatalf("%s: error must name the rejected cursor, got: %v", tc.name, err)
		}
	}
	if requests != 0 {
		t.Fatalf("a cursor request must never reach the server, got %d request(s)", requests)
	}
}

// ── GO-7: Emails.List pagination meta over the wire ─────────────────────────

func TestEmailsListCapturesEnvelopePaginationMeta(t *testing.T) {
	t.Parallel()

	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		// Real GET /v1/messages shape with meta (camelCase).
		_, _ = w.Write([]byte(`{"data":[{"id":"msg_1","from":"sender@example.com","to":["user@example.com"],"subject":"Hi","status":"delivered","tags":[],"metadata":null,"scheduled_at":null,"sent_at":"2026-10-06T12:00:01Z","created_at":"2026-10-06T12:00:00Z"}],"error":null,"meta":{"hasMore":true,"nextCursor":"deadbeef"}}`))
	})

	resp, err := client.Emails.List(context.Background())
	if err != nil {
		t.Fatalf("emails list: %v", err)
	}
	if len(resp.Messages) != 1 || resp.Messages[0].ID != "msg_1" {
		t.Fatalf("messages not decoded: %#v", resp.Messages)
	}
	if !resp.HasMore() || resp.NextCursor() != "deadbeef" {
		t.Fatalf("pagination meta dropped again (GO-7): hasMore=%v cursor=%q", resp.HasMore(), resp.NextCursor())
	}
	if resp.Pagination.Cursor != "deadbeef" || !resp.Pagination.HasMore {
		t.Fatalf("Pagination not populated: %#v", resp.Pagination)
	}
}

// ── GO-10: mounted domain routes ────────────────────────────────────────────

func TestDomainsDNSRecordsAndAuthStatus(t *testing.T) {
	t.Parallel()

	requests := 0
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		switch r.URL.Path {
		case "/v1/domains/dom_1/dns-records":
			// routes/domains.rs get_dns_records → DnsRecordsResponse.
			_, _ = w.Write([]byte(`{"domain":"mail.example.com","records":[{"record_type":"TXT","hostname":"_dmarc.mail.example.com","value":"v=DMARC1; p=none","priority":null},{"record_type":"CNAME","hostname":"am1._domainkey.mail.example.com","value":"am1.dkim.apexmail.ee","priority":10}]}`))
		case "/v1/domains/dom_1/auth-status":
			// get_auth_status → DomainAuthStatus.
			_, _ = w.Write([]byte(`{"domain":"mail.example.com","spf":{"status":"pass","value":"v=spf1 include:amazonses.com ~all","expected":"v=spf1 include:amazonses.com ~all","fix":null},"dkim":{"status":"pass","value":"am1.dkim.apexmail.ee","expected":"am1.dkim.apexmail.ee","fix":null},"dmarc":{"status":"fail","value":null,"expected":"v=DMARC1; p=none","fix":"Add a DMARC TXT record"},"mx":{"status":"pass","value":"inbound-smtp.eu-west-1.amazonaws.com","expected":"inbound-smtp.eu-west-1.amazonaws.com","fix":null},"return_path":{"status":"pass","value":"am1.dkim.apexmail.ee","expected":"am1.dkim.apexmail.ee","fix":null},"overall_status":"degraded"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	})

	records, err := client.Domains.DNSRecords(context.Background(), "dom_1")
	if err != nil {
		t.Fatalf("dns records: %v", err)
	}
	if records.Domain != "mail.example.com" || len(records.Records) != 2 {
		t.Fatalf("DnsRecordsResponse not decoded: %#v", records)
	}
	if records.Records[0].Type != "TXT" || records.Records[0].Name != "_dmarc.mail.example.com" || records.Records[0].Value != "v=DMARC1; p=none" {
		t.Fatalf("DnsRecord fields not mapped: %#v", records.Records[0])
	}
	if records.Records[1].Priority != 10 {
		t.Fatalf("DnsRecord priority not mapped: %#v", records.Records[1])
	}

	status, err := client.Domains.AuthStatus(context.Background(), "dom_1")
	if err != nil {
		t.Fatalf("auth status: %v", err)
	}
	if status.Domain != "mail.example.com" || status.OverallStatus != "degraded" {
		t.Fatalf("DomainAuthStatus not decoded: %#v", status)
	}
	if status.SPF.Status != "pass" || status.DMARC.Status != "fail" || status.DMARC.Expected != "v=DMARC1; p=none" || status.DMARC.Fix != "Add a DMARC TXT record" {
		t.Fatalf("AuthCheckResult fields not mapped: %#v", status)
	}
	if requests != 2 {
		t.Fatalf("expected 2 requests, got %d", requests)
	}
}

// ── GO-11: Retry-After on the typed rate-limit error ───────────────────────

func TestRateLimitErrorExposesRetryAfter(t *testing.T) {
	t.Parallel()

	// Integer seconds.
	if got := parseRetryAfter(&http.Response{Header: http.Header{"Retry-After": []string{"7"}}}); got != 7*time.Second {
		t.Fatalf("Retry-After seconds: got %v", got)
	}
	// HTTP-date.
	future := time.Now().Add(30 * time.Second).UTC().Format(time.RFC1123)
	if got := parseRetryAfter(&http.Response{Header: http.Header{"Retry-After": []string{future}}}); got <= 0 || got > 31*time.Second {
		t.Fatalf("Retry-After HTTP-date: got %v", got)
	}
	// Absent/garbage → zero.
	if got := parseRetryAfter(&http.Response{Header: http.Header{}}); got != 0 {
		t.Fatalf("absent Retry-After must be zero, got %v", got)
	}
	if got := parseRetryAfter(&http.Response{Header: http.Header{"Retry-After": []string{"garbage"}}}); got != 0 {
		t.Fatalf("garbage Retry-After must be zero, got %v", got)
	}

	err := classifyAPIError(&APIError{StatusCode: http.StatusTooManyRequests, Code: "RATE_LIMIT_EXCEEDED", Message: "slow down"}, 3*time.Second)
	rateLimitErr, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("expected *RateLimitError, got %T", err)
	}
	if rateLimitErr.RetryAfter != 3*time.Second {
		t.Fatalf("RetryAfter not surfaced: %v", rateLimitErr.RetryAfter)
	}
	if rateLimitErr.Code != "RATE_LIMIT_EXCEEDED" {
		t.Fatalf("embedded APIError lost: %#v", rateLimitErr.APIError)
	}
}

// A 429 response carrying Retry-After must reach callers as the typed error
// with the header parsed (wire-level, end-to-end through the retry loop).
func TestFinalRateLimitErrorCarriesRetryAfterHeader(t *testing.T) {
	t.Parallel()

	attempts := 0
	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"data":null,"error":{"code":"RATE_LIMIT_EXCEEDED","message":"slow down"},"meta":null}`))
	})

	_, err := client.Emails.Get(context.Background(), "msg_1")
	rateLimitErr, ok := err.(*RateLimitError)
	if !ok {
		t.Fatalf("expected *RateLimitError, got %T: %v", err, err)
	}
	if attempts != defaultMaxRetries+1 {
		t.Fatalf("expected %d attempts, got %d", defaultMaxRetries+1, attempts)
	}
	if rateLimitErr.RetryAfter != time.Second {
		t.Fatalf("Retry-After: 1 must surface as 1s, got %v", rateLimitErr.RetryAfter)
	}
}

// ── envelope meta merge must not corrupt object payloads ────────────────────

func TestDecodeAPIResponseStillMergesMetaIntoObjectPayloads(t *testing.T) {
	t.Parallel()

	body := []byte(`{"data":{"total_sent":10},"error":null,"meta":{"cached":true}}`)
	var out map[string]interface{}
	if err := decodeAPIResponse(body, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out["total_sent"] != float64(10) || out["cached"] != true {
		t.Fatalf("meta merge changed: %#v", out)
	}
}

// ── batch result shape must be the real {index, id?, status, error?} ────────

func TestBatchResultsDecodeRealAcceptedAndRejectedItems(t *testing.T) {
	t.Parallel()

	_, client := newTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages/batch" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		body, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(body, &payload)
		if _, present := payload["messages"].([]any); !present {
			t.Fatalf("batch body must carry messages[]: %s", body)
		}
		_, _ = w.Write([]byte(`{"data":{"accepted":1,"rejected":1,"results":[{"index":0,"id":"msg_1","status":"queued"},{"index":1,"status":"rejected","error":"sender domain is not ready for the configured delivery transport"}]},"error":null}`))
	})

	resp, err := client.Emails.Batch(context.Background(), &BatchSendRequest{Messages: []*SendEmailRequest{
		{From: EmailAddress{Email: "a@example.com"}, To: []EmailAddress{{Email: "x@example.com"}}, Subject: "1", Text: "x"},
		{From: EmailAddress{Email: "a@example.com"}, To: []EmailAddress{{Email: "y@example.com"}}, Subject: "2", Text: "x"},
	}})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if resp.Accepted != 1 || resp.Rejected != 1 || len(resp.Results) != 2 {
		t.Fatalf("batch summary not decoded: %#v", resp)
	}
	if resp.Results[0].Status != "queued" || resp.Results[0].ID != "msg_1" {
		t.Fatalf("accepted item not decoded: %#v", resp.Results[0])
	}
	if resp.Results[1].Status != "rejected" || resp.Results[1].Error == "" || resp.Results[1].ID != "" {
		t.Fatalf("rejected item not decoded: %#v", resp.Results[1])
	}
}
