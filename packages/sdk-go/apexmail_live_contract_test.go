package apexmail

// LiveStackContractTest — env-gated, mirroring the other four SDKs' live
// contract suites (Java LiveStackContractTest, PHP test.php live mode). It
// runs only when APEXMAIL_LIVE_API_KEY and APEXMAIL_LIVE_BASE_URL are set and
// otherwise skips with a notice, so the hermetic `go test ./...` run is
// unaffected.
//
// Usage against the local dogfood stack (HTTP :8080 fronted by the TLS proxy
// at :8443, self-signed cert):
//
//	APEXMAIL_LIVE_API_KEY=am_live_… \
//	APEXMAIL_LIVE_BASE_URL=https://127.0.0.1:8443 \
//	APEXMAIL_LIVE_CA_PEM=/tmp/sdklive/tls/cert.pem \
//	go test -run TestLiveStackContract -v ./...
//
// The test paces itself (the shared dev stack's adaptive DDoS middleware
// answers bursts with 429) and drives the fixed surfaces end-to-end: send +
// idempotent replay, messages list meta, both events shapes, stats,
// timeseries, analytics volume, api-keys list, domain DNS-records/auth-status,
// and the client-side refusals (cursor, template fields).

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func liveTestClient(t *testing.T) *Client {
	t.Helper()
	key := strings.TrimSpace(os.Getenv("APEXMAIL_LIVE_API_KEY"))
	base := strings.TrimSpace(os.Getenv("APEXMAIL_LIVE_BASE_URL"))
	if key == "" || base == "" {
		t.Skip("live stack contract test skipped: set APEXMAIL_LIVE_API_KEY and APEXMAIL_LIVE_BASE_URL (and APEXMAIL_LIVE_CA_PEM for a self-signed endpoint)")
	}
	cfg := Config{BaseURL: base, Timeout: 30 * time.Second}
	if caPEM := strings.TrimSpace(os.Getenv("APEXMAIL_LIVE_CA_PEM")); caPEM != "" {
		pemBytes, err := os.ReadFile(caPEM)
		if err != nil {
			t.Fatalf("read APEXMAIL_LIVE_CA_PEM: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pemBytes) {
			t.Fatalf("APEXMAIL_LIVE_CA_PEM %s carries no certificate", caPEM)
		}
		cfg.HTTPClient = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{RootCAs: pool},
			},
		}
	}
	client, err := New(key, cfg)
	if err != nil {
		t.Fatalf("live client: %v", err)
	}
	return client
}

func TestLiveStackContract(t *testing.T) {
	client := liveTestClient(t)
	ctx := context.Background()
	pause := func() { time.Sleep(400 * time.Millisecond) }

	// 1. Send with a caller-supplied idempotency key; replaying the same key
	// must return the SAME message id (server's durable idempotency ledger,
	// reachable only when the SDK sends the real `Idempotency-Key` header —
	// GO-1).
	key := fmt.Sprintf("go-live-%d", time.Now().UnixNano())
	send := func() *SendEmailResponse {
		t.Helper()
		resp, err := client.Emails.Send(ctx, &SendEmailRequest{
			From:    EmailAddress{Email: "sender@sdkfix-live-test.example"},
			To:      []EmailAddress{{Email: "go-live@example.test"}},
			Subject: "Go SDK live contract",
			HTML:    "<p>live contract</p>",
			Tags:    []string{"sdk-live"},
			ReplyTo: &EmailAddress{Email: "reply@sdkfix-live-test.example"},
		}, SendOptions{IdempotencyKey: key})
		if err != nil {
			t.Fatalf("live send: %v", err)
		}
		return resp
	}
	first := send()
	if first.ID == "" || first.Status == "" || first.CreatedAt == "" {
		t.Fatalf("send did not decode the flat {id,status,created_at}: %#v", first)
	}
	pause()
	replay := send()
	if replay.ID != first.ID {
		t.Fatalf("Idempotency-Key was not honoured: first=%s replay=%s", first.ID, replay.ID)
	}
	t.Logf("PASS send/replay id=%s status=%s", first.ID, first.Status)

	// 2. Get decodes the flat MessageDetail.
	pause()
	detail, err := client.Emails.Get(ctx, first.ID)
	if err != nil {
		t.Fatalf("live get: %v", err)
	}
	if detail.ID != first.ID || detail.Subject != "Go SDK live contract" {
		t.Fatalf("get mismatch: %#v", detail)
	}
	t.Logf("PASS get id=%s", detail.ID)

	// 3. Messages list: bare array + envelope meta captured (GO-7).
	pause()
	limit := 5
	list, err := client.Emails.List(ctx, ListEmailsOptions{Limit: &limit})
	if err != nil {
		t.Fatalf("live list: %v", err)
	}
	if list.Messages == nil {
		t.Fatalf("messages list decoded nil (array shape broken)")
	}
	t.Logf("PASS messages.list n=%d hasMore=%v nextCursor=%q", len(list.Messages), list.HasMore(), list.NextCursor())

	// 4. Events list decodes the bare array (GO-2); when events exist, Get
	// decodes the flat object (GO-5) and GetByMessage path is exercised.
	pause()
	events, err := client.Events.List(ctx, ListEventsOptions{})
	if err != nil {
		t.Fatalf("live events list: %v (bare-array decode)", err)
	}
	t.Logf("PASS events.list n=%d", len(events.Events))
	if len(events.Events) > 0 {
		pause()
		event, err := client.Events.Get(ctx, events.Events[0].ID)
		if err != nil {
			t.Fatalf("live events get: %v", err)
		}
		if event.ID != events.Events[0].ID {
			t.Fatalf("events get mismatch: %#v", event)
		}
		if event.EventType == "" {
			t.Fatalf("events get decoded an empty event (snake_case tags broken): %#v", event)
		}
		t.Logf("PASS events.get id=%s type=%s", event.ID, event.EventType)
		if events.Events[0].MessageID != "" {
			pause()
			byMessage, err := client.Events.GetByMessage(ctx, events.Events[0].MessageID)
			if err != nil {
				t.Fatalf("live events by message: %v", err)
			}
			t.Logf("PASS events.byMessage n=%d", len(byMessage.Events))
		}
	}

	// 5. Events stats (object) and timeseries (bare array) with the accepted
	// {from, to} filters only (GO-9).
	from := time.Now().Add(-7 * 24 * time.Hour).UTC().Format(time.RFC3339)
	to := time.Now().UTC().Format(time.RFC3339)
	pause()
	stats, err := client.Events.Stats(ctx, EventAggregateOptions{From: from, To: to})
	if err != nil {
		t.Fatalf("live events stats: %v", err)
	}
	if _, ok := stats["total"]; !ok {
		t.Fatalf("stats did not decode the EventStats object: %#v", stats)
	}
	pause()
	points, err := client.Events.Timeseries(ctx, EventAggregateOptions{From: from, To: to})
	if err != nil {
		t.Fatalf("live events timeseries: %v (bare-array decode)", err)
	}
	t.Logf("PASS events.stats/timeseries points=%d", len(points))

	// 6. Analytics volume decodes the array inside the envelope (GO-3).
	pause()
	volume, err := client.Analytics.Volume(ctx, AnalyticsOptions{From: from, To: to})
	if err != nil {
		t.Fatalf("live analytics volume: %v (array-in-envelope decode)", err)
	}
	t.Logf("PASS analytics.volume points=%d", len(volume))

	// 7. API keys list decodes the bare array (GO-4).
	pause()
	keys, err := client.APIKeys.List(ctx, ListAPIKeysOptions{Limit: 10})
	if err != nil {
		t.Fatalf("live api keys list: %v", err)
	}
	if len(keys) == 0 || keys[0].ID == "" || keys[0].KeyPrefix == "" {
		t.Fatalf("api keys list decoded no usable ApiKeyInfo: %#v", keys)
	}
	t.Logf("PASS apiKeys.list n=%d first=%s", len(keys), keys[0].ID)

	// 8. Domain list (bare array) + the two previously unmounted routes
	// (GO-10). DNS-records may answer 409 until DKIM material exists; both
	// outcomes prove the route is mounted and decoded.
	pause()
	domains, err := client.Domains.List(ctx)
	if err != nil {
		t.Fatalf("live domains list: %v", err)
	}
	t.Logf("PASS domains.list n=%d", len(domains.Domains))
	if len(domains.Domains) > 0 {
		domainID := domains.Domains[0].ID
		pause()
		records, err := client.Domains.DNSRecords(ctx, domainID)
		if err != nil {
			if _, isConflict := err.(*ConflictError); !isConflict {
				t.Fatalf("live domains.dnsRecords: %v", err)
			}
			t.Logf("PASS domains.dnsRecords route mounted (409 until DKIM material exists)")
		} else if records.Domain == "" || records.Records == nil {
			t.Fatalf("dns-records decoded empty: %#v", records)
		} else {
			t.Logf("PASS domains.dnsRecords n=%d", len(records.Records))
		}
		pause()
		authStatus, err := client.Domains.AuthStatus(ctx, domainID)
		if err != nil {
			t.Fatalf("live domains.authStatus: %v", err)
		}
		if authStatus.Domain == "" || authStatus.OverallStatus == "" {
			t.Fatalf("auth-status decoded empty: %#v", authStatus)
		}
		t.Logf("PASS domains.authStatus overall=%s", authStatus.OverallStatus)
	}

	// 9. Client-side refusals never reach the wire: cursor on the
	// deny_unknown_fields routes (GO-8) and template fields on send (GO-6).
	if _, err := client.Events.List(ctx, ListEventsOptions{Cursor: "abc"}); err == nil || !strings.Contains(err.Error(), "cursor") {
		t.Fatalf("cursor must be rejected client-side, got: %v", err)
	}
	if _, err := client.Emails.Send(ctx, &SendEmailRequest{
		From:       EmailAddress{Email: "sender@sdkfix-live-test.example"},
		To:         []EmailAddress{{Email: "go-live@example.test"}},
		Subject:    "must not send",
		HTML:       "<p>x</p>",
		TemplateID: "tpl_must_be_rejected",
	}); err == nil || !strings.Contains(err.Error(), "template_id") {
		t.Fatalf("template_id must be rejected client-side, got: %v", err)
	}
	t.Logf("PASS client-side refusals (cursor, template_id)")
}
