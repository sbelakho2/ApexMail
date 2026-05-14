package apexmail

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTemplatesRenderUsesVariablesPayload(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST, got %s", r.Method)
		}
		if r.URL.Path != "/v1/templates/template-123/render" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if _, ok := payload["data"]; ok {
			t.Fatalf("unexpected legacy data key in payload: %s", string(body))
		}
		variables, ok := payload["variables"].(map[string]any)
		if !ok {
			t.Fatalf("missing variables map in payload: %s", string(body))
		}
		if variables["first_name"] != "Alice" {
			t.Fatalf("unexpected variables payload: %#v", variables)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subject":"Hello Alice","html":"<p>Hello Alice</p>","text":"Hello Alice"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	resp, err := client.Templates.Render(context.Background(), "template-123", map[string]interface{}{
		"first_name": "Alice",
	})
	if err != nil {
		t.Fatalf("render template: %v", err)
	}
	if resp.Subject != "Hello Alice" {
		t.Fatalf("unexpected response: %#v", resp)
	}
}

func TestTemplatesRenderNilDataSendsEmptyVariablesObject(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		variables, ok := payload["variables"].(map[string]any)
		if !ok {
			t.Fatalf("missing variables object: %s", string(body))
		}
		if len(variables) != 0 {
			t.Fatalf("expected empty variables object, got %#v", variables)
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"subject":"Hello","html":"<p>Hello</p>","text":"Hello"}`))
	}))
	defer server.Close()

	client, err := New("am_live_1234567890abcdef", Config{
		BaseURL:    server.URL,
		HTTPClient: server.Client(),
	})
	if err != nil {
		t.Fatalf("create client: %v", err)
	}

	if _, err := client.Templates.Render(context.Background(), "template-123", nil); err != nil {
		t.Fatalf("render template with nil data: %v", err)
	}
}