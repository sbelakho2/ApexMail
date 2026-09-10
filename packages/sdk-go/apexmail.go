// Package apexmail is the official Go SDK for the ApexMail transactional email API.
//
// Usage:
//
//	client := apexmail.New("am_live_xxxx")
//	resp, err := client.Emails.Send(ctx, &apexmail.SendEmailRequest{
//	    From:    apexmail.EmailAddress{Email: "hello@example.com"},
//	    To:      []apexmail.EmailAddress{{Email: "user@example.com"}},
//	    Subject: "Hello!",
//	    HTML:    "<h1>Hello World</h1>",
//	})
package apexmail

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultBaseURL               = "https://api.apexmail.ee"
	defaultTimeout               = 30 * time.Second
	sdkVersion                   = "1.0.0"
	defaultMaxResponseBytes      = 20 * 1024 * 1024
	defaultMaxRetries            = 3
	defaultInitialBackoff        = 500 * time.Millisecond
	defaultMaxBackoff            = 5 * time.Second
	maxRetryAfterDelay           = 120 * time.Second
	defaultIdleConnTimeout       = 90 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultMaxIdleConns          = 100
	defaultMaxIdleConnsPerHost   = 10
	defaultExpectContinueTimeout = 1 * time.Second
)

var apiKeyPattern = regexp.MustCompile(`^am_(live|test)_[A-Za-z0-9]{16,}$`)
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Control characters (C0 + DEL) stripped from caller-supplied header values.
var controlCharRegex = regexp.MustCompile(`[\x00-\x1F\x7F]`)

// Client is the root ApexMail API client. Use New() to create one.
type Client struct {
	mu               sync.RWMutex
	apiKey           string
	apiKeyErr        error
	baseURL          string
	timeout          time.Duration
	httpClient       *http.Client
	maxResponseBytes int64
	Emails           *EmailsAPI
	Domains          *DomainsAPI
	Webhooks         *WebhooksAPI
	Templates        *TemplatesAPI
	Suppressions     *SuppressionsAPI
	Events           *EventsAPI
	Analytics        *AnalyticsAPI
	APIKeys          *APIKeysAPI
}

// Config holds optional configuration for the client.
type Config struct {
	BaseURL          string
	HTTPClient       *http.Client
	Timeout          time.Duration
	MaxResponseBytes int64
}

// New creates a new ApexMail client with the provided API key.
// Returns an error if the API key is invalid or the base URL does not use HTTPS.
func New(apiKey string, cfg ...Config) (*Client, error) {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}
	baseURL := defaultBaseURL
	if c.BaseURL != "" {
		baseURL = c.BaseURL
	}
	// Strip trailing slash to prevent double slashes when joining paths.
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("apexmail: baseURL %q must use HTTPS", baseURL)
	}
	if err := validateAPIKey(apiKey); err != nil {
		return nil, err
	}
	timeout := defaultTimeout
	if c.Timeout > 0 {
		timeout = c.Timeout
	}
	maxResponseBytes := int64(defaultMaxResponseBytes)
	if c.MaxResponseBytes > 0 {
		maxResponseBytes = c.MaxResponseBytes
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = newDefaultHTTPClient(timeout)
	} else {
		httpClient = normalizeHTTPClient(httpClient, timeout)
	}
	cl := &Client{
		apiKey:           apiKey,
		baseURL:          baseURL,
		timeout:          timeout,
		httpClient:       httpClient,
		apiKeyErr:        nil, // validated above
		maxResponseBytes: maxResponseBytes,
	}
	cl.Emails = &EmailsAPI{client: cl}
	cl.Domains = &DomainsAPI{client: cl}
	cl.Webhooks = &WebhooksAPI{client: cl}
	cl.Templates = &TemplatesAPI{client: cl}
	cl.Suppressions = &SuppressionsAPI{client: cl}
	cl.Events = &EventsAPI{client: cl}
	cl.Analytics = &AnalyticsAPI{client: cl}
	cl.APIKeys = &APIKeysAPI{client: cl}
	return cl, nil
}

// String returns a redacted representation for safe logging.
func (c *Client) String() string {
	key := c.apiKey
	if len(key) > 8 {
		key = key[:4] + "…" + key[len(key)-4:]
	}
	return fmt.Sprintf("Client{apiKey=%s baseURL=%s}", key, c.baseURL)
}

// GoString returns a redacted representation for %#v formatting (fmt.GoStringer).
func (c *Client) GoString() string {
	return c.String()
}

func newDefaultHTTPClient(timeout time.Duration) *http.Client {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          defaultMaxIdleConns,
		MaxIdleConnsPerHost:   defaultMaxIdleConnsPerHost,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ExpectContinueTimeout: defaultExpectContinueTimeout,
	}
	return &http.Client{
		Timeout:   timeout,
		Transport: transport,
	}
}

func normalizeHTTPClient(client *http.Client, timeout time.Duration) *http.Client {
	if client == nil {
		return newDefaultHTTPClient(timeout)
	}
	normalized := *client
	if normalized.Timeout == 0 {
		normalized.Timeout = timeout
	}

	transport, ok := normalized.Transport.(*http.Transport)
	if !ok || transport == nil {
		return &normalized
	}

	clone := transport.Clone()
	if clone.MaxIdleConns == 0 {
		clone.MaxIdleConns = defaultMaxIdleConns
	}
	if clone.MaxIdleConnsPerHost == 0 {
		clone.MaxIdleConnsPerHost = defaultMaxIdleConnsPerHost
	}
	if clone.IdleConnTimeout == 0 {
		clone.IdleConnTimeout = defaultIdleConnTimeout
	}
	if clone.TLSHandshakeTimeout == 0 {
		clone.TLSHandshakeTimeout = defaultTLSHandshakeTimeout
	}
	if clone.ExpectContinueTimeout == 0 {
		clone.ExpectContinueTimeout = defaultExpectContinueTimeout
	}

	normalized.Transport = clone
	return &normalized
}

func validateAPIKey(apiKey string) error {
	if apiKey == "" || !apiKeyPattern.MatchString(apiKey) {
		return fmt.Errorf("apexmail: invalid API key format")
	}
	return nil
}

func validateSendEmailRequest(req *SendEmailRequest) error {
	if req == nil {
		return fmt.Errorf("apexmail: send request is required")
	}
	if req.From.Email == "" || !isValidEmailAddress(req.From.Email) {
		return fmt.Errorf("apexmail: invalid from address")
	}
	if len(req.To) == 0 {
		return fmt.Errorf("apexmail: at least one recipient is required")
	}
	for _, recipient := range req.To {
		if recipient.Email == "" || !isValidEmailAddress(recipient.Email) {
			return fmt.Errorf("apexmail: invalid to address")
		}
	}
	for _, recipient := range req.CC {
		if recipient.Email == "" || !isValidEmailAddress(recipient.Email) {
			return fmt.Errorf("apexmail: invalid cc address")
		}
	}
	for _, recipient := range req.BCC {
		if recipient.Email == "" || !isValidEmailAddress(recipient.Email) {
			return fmt.Errorf("apexmail: invalid bcc address")
		}
	}
	if req.Subject == "" {
		return fmt.Errorf("apexmail: subject is required")
	}
	if req.HTML == "" && req.Text == "" {
		// The API's SendMessageRequest has no templateId field, so a
		// template-only request cannot be serialized into a valid body.
		if req.TemplateID != "" {
			return fmt.Errorf("apexmail: html or text body is required (templateId is not supported by the send API)")
		}
		return fmt.Errorf("apexmail: html or text is required")
	}
	return nil
}

func isValidEmailAddress(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	addr, err := mail.ParseAddress(trimmed)
	if err != nil {
		return false
	}
	// SDK-G L5: reject display-name forms like `Display Name <a@b.c>` — the
	// caller must pass the bare address (use EmailAddress{Name: ...} for
	// display names). mail.ParseAddress accepts them, so require the parsed
	// address to be identical to the input, then re-validate the address
	// itself against the plain-address pattern.
	return addr.Address == trimmed && emailPattern.MatchString(addr.Address)
}

// newUUID4 generates a random RFC 4122 version-4 UUID using crypto/rand.
// Used for automatic idempotency keys on send endpoints (SDK-B).
func newUUID4() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("apexmail: generate uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// WebhookSignatureOptions configures webhook signature verification.
//
// The platform (worker-processors/src/webhook/processor.rs) delivers:
//
//	X-ApexMail-Signature: sha256=<hex hmac>
//	X-ApexMail-Timestamp: <milliseconds since epoch>
//
// and signs the exact string "{timestamp_millis}.{payload}". Pass the
// X-ApexMail-Timestamp header in Timestamp; milliseconds are auto-detected
// (and checked against time.Now().UnixMilli()) while the signed string
// always uses the timestamp digits verbatim.
type WebhookSignatureOptions struct {
	Payload   []byte
	Signature string
	Secret    string
	Timestamp string
	Tolerance time.Duration
}

// msDetectionCutoff: timestamps above this cannot be epoch seconds
// (2001-09-09); below it they cannot be epoch milliseconds.
const msDetectionCutoff = int64(1_000_000_000_000)

// VerifyWebhookSignature validates a webhook payload signature using HMAC-SHA256.
func VerifyWebhookSignature(opts WebhookSignatureOptions) bool {
	if len(opts.Payload) == 0 || opts.Signature == "" || opts.Secret == "" {
		return false
	}

	timestamp, signature := parseWebhookSignature(opts.Signature)
	if opts.Timestamp != "" {
		timestamp = strings.TrimSpace(opts.Timestamp)
	}
	if timestamp == "" || signature == "" {
		return false
	}

	ts, err := strconv.ParseInt(timestamp, 10, 64)
	if err != nil {
		return false
	}
	if opts.Tolerance <= 0 {
		opts.Tolerance = 5 * time.Minute
	}
	// Auto-detect seconds vs milliseconds: the platform sends milliseconds.
	now := time.Now().Unix()
	tolerance := int64(opts.Tolerance.Seconds())
	if ts > msDetectionCutoff {
		now = time.Now().UnixMilli()
		tolerance *= 1000
	}
	if absInt64(now-ts) > tolerance {
		return false
	}

	// Sign with the timestamp digits EXACTLY as delivered (milliseconds on
	// the platform path) — never a normalized form.
	signedPayload := timestamp + "." + string(opts.Payload)
	mac := hmac.New(sha256.New, []byte(opts.Secret))
	_, _ = mac.Write([]byte(signedPayload))
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(expected), []byte(signature))
}

func parseWebhookSignature(signatureHeader string) (string, string) {
	trimmed := strings.TrimSpace(signatureHeader)
	if strings.Contains(trimmed, "t=") && strings.Contains(trimmed, "v1=") {
		var timestamp string
		var signature string
		parts := strings.Split(trimmed, ",")
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if strings.HasPrefix(part, "t=") {
				timestamp = strings.TrimPrefix(part, "t=")
			}
			if strings.HasPrefix(part, "v1=") {
				signature = strings.TrimPrefix(part, "v1=")
			}
		}
		return timestamp, signature
	}
	if strings.HasPrefix(trimmed, "sha256=") {
		return "", strings.TrimPrefix(trimmed, "sha256=")
	}
	return "", trimmed
}

func absInt64(value int64) int64 {
	if value < 0 {
		return -value
	}
	return value
}

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}, idempotencyKey ...string) error {
	c.mu.RLock()
	apiKeyErr := c.apiKeyErr
	apiKey := c.apiKey
	baseURL := c.baseURL
	httpClient := c.httpClient
	maxResponseBytes := c.maxResponseBytes
	timeout := c.timeout
	c.mu.RUnlock()

	if apiKeyErr != nil {
		return apiKeyErr
	}

	// Duplicate-side-effect protection (SDK-B, matching the PHP SDK): every
	// mutating POST with a body that has no caller-supplied key gets a UUID
	// generated BEFORE the retry loop, so all attempts of this logical
	// operation present the same key and the server can deduplicate.
	if len(idempotencyKey) == 0 || idempotencyKey[0] == "" {
		if method == http.MethodPost && body != nil {
			key, err := newUUID4()
			if err != nil {
				return err
			}
			idempotencyKey = []string{key}
		}
	}

	var bodyBytes []byte
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("apexmail: marshal request body: %w", err)
		}
		bodyBytes = b
	}

	for attempt := 0; attempt <= defaultMaxRetries; attempt++ {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return &NetworkError{Message: "request canceled", Cause: ctxErr}
		}

		var bodyReader io.Reader
		if len(bodyBytes) > 0 {
			bodyReader = bytes.NewReader(bodyBytes)
		}

		// Per-ATTEMPT request timeout (F9): the configured timeout bounds a
		// single HTTP request, not the whole retry loop. Wrapping the loop
		// (including the retry sleeps) meant an honored Retry-After of e.g.
		// 60s could never execute inside a 30s budget — the retry was
		// canceled mid-sleep and surfaced as a generic NetworkError.
		reqCtx := ctx
		var cancel context.CancelFunc
		if timeout > 0 {
			reqCtx, cancel = context.WithTimeout(ctx, timeout)
		}
		req, err := http.NewRequestWithContext(reqCtx, method, baseURL+path, bodyReader)
		if err != nil {
			if cancel != nil {
				cancel()
			}
			return &NetworkError{Message: "create request: " + err.Error(), Cause: err}
		}
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("User-Agent", "apexmail-go/"+sdkVersion)
		if bodyReader != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if len(idempotencyKey) > 0 && idempotencyKey[0] != "" {
			// Header injection: strip control bytes from caller-supplied keys.
			safeKey := controlCharRegex.ReplaceAllString(idempotencyKey[0], "")
			if len(safeKey) > 128 {
				safeKey = safeKey[:128]
			}
			req.Header.Set("X-Idempotency-Key", safeKey)
		}

		resp, err := httpClient.Do(req)
		if cancel != nil {
			cancel()
		}
		if err != nil {
			if attempt < defaultMaxRetries {
				if sleepErr := sleepWithContext(ctx, jitteredDelay(calculateBackoff(attempt))); sleepErr != nil {
					return &NetworkError{Message: "request canceled", Cause: sleepErr}
				}
				continue
			}
			return &NetworkError{Message: err.Error(), Cause: err}
		}

		respBody, readErr := func() ([]byte, error) {
			defer resp.Body.Close()
			return readLimitedBody(resp, maxResponseBytes)
		}()
		if readErr != nil {
			return readErr
		}

		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= http.StatusInternalServerError {
			if attempt < defaultMaxRetries {
				// The sleep runs on the PARENT context (no timeout wrapper),
				// so an honored Retry-After — capped at maxRetryAfterDelay —
				// can actually elapse before the next attempt.
				if sleepErr := sleepWithContext(ctx, jitteredDelay(retryDelay(resp, attempt))); sleepErr != nil {
					return &NetworkError{Message: "request canceled", Cause: sleepErr}
				}
				continue
			}
			// Final 429 attempt: surface as the typed RateLimitError (via
			// classifyAPIError below), never a generic NetworkError.
		}

		if resp.StatusCode >= 400 {
			apiErr := parseAPIError(respBody, resp.StatusCode)
			switch e := apiErr.(type) {
			case *APIError:
				return classifyAPIError(e)
			default:
				return apiErr
			}
		}
		if out != nil && len(respBody) > 0 {
			if err := decodeAPIResponse(respBody, out); err != nil {
				return fmt.Errorf("apexmail: unmarshal response: %w", err)
			}
		}
		return nil
	}

	return &NetworkError{Message: "request failed after retries", Cause: nil}
}

func readLimitedBody(resp *http.Response, maxBytes int64) ([]byte, error) {
	limited := io.LimitReader(resp.Body, maxBytes)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return nil, &NetworkError{Message: "read response body: " + err.Error(), Cause: err}
	}
	extra := make([]byte, 1)
	n, readErr := resp.Body.Read(extra)
	if readErr != nil && readErr != io.EOF {
		return nil, &NetworkError{Message: "read response body overflow: " + readErr.Error(), Cause: readErr}
	}
	if n > 0 {
		return nil, &NetworkError{Message: "response body too large", Cause: nil}
	}
	return respBody, nil
}

// retryDelay computes the delay before the next retry using:
//
//	delay = min(max(retryAfterSeconds, baseDelay * attempt²), maxRetryAfterDelay)
//
// The server's Retry-After header (integer seconds or HTTP-date) is honored
// in full — capped at a sane maximum of 120s (SDK-F: previously the server's
// value was silently truncated to defaultMaxBackoff = 5s). Quadratic backoff
// on its own remains capped at defaultMaxBackoff.
func retryDelay(resp *http.Response, attempt int) time.Duration {
	retryAfter := resp.Header.Get("Retry-After")

	// Compute quadratic backoff: baseDelay * attempt² (capped at 5s)
	backoff := calculateBackoff(attempt)

	if retryAfter == "" {
		return backoff
	}

	// Try integer seconds (most common)
	if seconds, err := strconv.Atoi(retryAfter); err == nil {
		if d := time.Duration(seconds) * time.Second; d > backoff {
			backoff = d
		}
		return capRetryDelay(backoff)
	}

	// Try HTTP-date format (RFC 1123)
	for _, layout := range []string{time.RFC1123, time.RFC1123Z} {
		if t, err := time.Parse(layout, retryAfter); err == nil {
			if d := time.Until(t); d > backoff {
				backoff = d
			}
			return capRetryDelay(backoff)
		}
	}

	// Unparseable header — fall back to quadratic backoff
	return backoff
}

// capRetryDelay bounds the total retry delay at maxRetryAfterDelay.
func capRetryDelay(delay time.Duration) time.Duration {
	if delay < 0 {
		return 0
	}
	if delay > maxRetryAfterDelay {
		return maxRetryAfterDelay
	}
	return delay
}

// calculateBackoff computes quadratic backoff: baseDelay * attempt²,
// capped at defaultMaxBackoff. Used when no Retry-After header is present.
//
// attempt is the retry NUMBER about to run (0 = first retry): the first
// retry uses attempt 1 — a 0-based exponent produced a 0s delay, an
// immediate hammer at a server that had just said "slow down" (matching
// the PHP SDK's computeRetryDelay(max(1, attempt)) fix).
func calculateBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	if attempt > 20 {
		attempt = 20
	}
	delay := defaultInitialBackoff * time.Duration(attempt*attempt)
	if delay > defaultMaxBackoff {
		return defaultMaxBackoff
	}
	return delay
}

// jitteredDelay applies up to ±20% jitter so clients retrying in lockstep
// spread out (thundering herd). The delay is never shortened by more than
// 20%, so an honored Retry-After window is preserved.
func jitteredDelay(delay time.Duration) time.Duration {
	if delay <= 0 {
		return 0
	}
	jitter := delay / 5
	var delta int64
	if jitter > 0 {
		// crypto/rand is already imported; math/rand needs seeding care, so
		// derive a small random factor from crypto/rand.
		var b [1]byte
		if _, err := rand.Read(b[:]); err == nil {
			delta = int64(b[0]%201) - 100 // -100..100 → -100%..100% of jitter
		}
	}
	return time.Duration(int64(delay) + delta*int64(jitter)/100)
}

func sleepWithContext(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
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

// APIError represents a structured API error response
type APIError struct {
	StatusCode int
	Code       string   `json:"code"`
	Message    string   `json:"message"`
	Details    []string `json:"details,omitempty"`
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("apexmail API error: %s - %s", e.Code, e.Message)
	}
	return fmt.Sprintf("apexmail: %s (status: %d)", e.Message, e.StatusCode)
}

// apiErrorResponse is the JSON envelope from the API:
//
//	{"data":null,"error":{"code":"...","message":"...","details":null},"meta":null}
type apiErrorResponse struct {
	Data  json.RawMessage `json:"data"`
	Error *APIError       `json:"error"`
	Meta  json.RawMessage `json:"meta"`
}

type apiSuccessResponse struct {
	Data  json.RawMessage `json:"data"`
	Error *APIError       `json:"error"`
	Meta  json.RawMessage `json:"meta"`
}

// parseAPIError attempts to parse an API error from an HTTP response body.
func parseAPIError(body []byte, statusCode int) error {
	var errResp apiErrorResponse
	if err := json.Unmarshal(body, &errResp); err == nil && errResp.Error != nil {
		errResp.Error.StatusCode = statusCode
		if errResp.Error.Message == "" {
			errResp.Error.Message = http.StatusText(statusCode)
		}
		return errResp.Error
	}

	var legacy struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &legacy); err == nil {
		message := legacy.Error
		if message == "" {
			message = legacy.Message
		}
		if message != "" {
			return &APIError{
				StatusCode: statusCode,
				Code:       apiErrorCodeFromStatus(statusCode),
				Message:    message,
			}
		}
	}

	return &APIError{
		StatusCode: statusCode,
		Code:       "INVALID_ERROR_PAYLOAD",
		Message:    fmt.Sprintf("HTTP %d: %s", statusCode, string(body)),
	}
}

func decodeAPIResponse(body []byte, out interface{}) error {
	var envelope apiSuccessResponse
	if err := json.Unmarshal(body, &envelope); err == nil && isAPIEnvelope(envelope) {
		if envelope.Error != nil {
			return envelope.Error
		}
		if len(envelope.Data) == 0 || string(envelope.Data) == "null" {
			return nil
		}
		payload := mergeEnvelopeMeta(envelope.Data, envelope.Meta)
		return json.Unmarshal(payload, out)
	}

	return json.Unmarshal(body, out)
}

func isAPIEnvelope(envelope apiSuccessResponse) bool {
	return envelope.Data != nil || envelope.Error != nil || envelope.Meta != nil
}

func mergeEnvelopeMeta(data json.RawMessage, meta json.RawMessage) json.RawMessage {
	if len(meta) == 0 || string(meta) == "null" {
		return data
	}

	var dataObject map[string]json.RawMessage
	if err := json.Unmarshal(data, &dataObject); err != nil || dataObject == nil {
		return data
	}

	// Merge all meta fields into data (overwriting only if data doesn't have the key).
	// This supports any metadata the API returns (pagination, totals, etc.)
	// without assuming which specific keys exist.
	var metaObject map[string]json.RawMessage
	if err := json.Unmarshal(meta, &metaObject); err == nil && metaObject != nil {
		for key, val := range metaObject {
			if _, exists := dataObject[key]; !exists {
				dataObject[key] = val
			}
		}
	}

	merged, err := json.Marshal(dataObject)
	if err != nil {
		return data
	}
	return merged
}

func apiErrorCodeFromStatus(statusCode int) string {
	switch statusCode {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusRequestTimeout:
		return "REQUEST_TIMEOUT"
	case http.StatusRequestEntityTooLarge:
		return "PAYLOAD_TOO_LARGE"
	case http.StatusTooManyRequests:
		return "RATE_LIMIT_EXCEEDED"
	case http.StatusServiceUnavailable:
		return "SERVICE_UNAVAILABLE"
	case http.StatusInternalServerError:
		return "INTERNAL_ERROR"
	default:
		if statusCode >= http.StatusInternalServerError {
			return "INTERNAL_ERROR"
		}
		return "HTTP_ERROR"
	}
}

func classifyAPIError(err *APIError) error {
	switch {
	case err.StatusCode == http.StatusUnauthorized || err.Code == "UNAUTHORIZED" || err.Code == "INVALID_API_KEY" || err.Code == "TOKEN_EXPIRED" || err.Code == "TOKEN_BLACKLISTED":
		return &AuthenticationError{APIError: err}
	case err.StatusCode == http.StatusForbidden || err.Code == "FORBIDDEN":
		return &ForbiddenError{APIError: err}
	case err.StatusCode == http.StatusNotFound || err.Code == "NOT_FOUND":
		return &NotFoundError{APIError: err}
	case err.StatusCode == http.StatusConflict || err.Code == "CONFLICT":
		return &ConflictError{APIError: err}
	case err.Code == "VALIDATION_ERROR" || err.Code == "INVALID_INPUT" || err.StatusCode == http.StatusBadRequest:
		return &ValidationError{APIError: err}
	case err.StatusCode == http.StatusTooManyRequests || err.Code == "RATE_LIMIT_EXCEEDED" || err.Code == "QUOTA_EXCEEDED":
		return &RateLimitError{APIError: err}
	default:
		return err
	}
}

// Typed error subtypes for specific HTTP status codes.

// AuthenticationError is returned when the API key is missing, invalid, or revoked (HTTP 401).
type AuthenticationError struct{ *APIError }

// ForbiddenError is returned when the API key lacks the required scopes (HTTP 403).
type ForbiddenError struct{ *APIError }

// NotFoundError is returned when the requested resource does not exist (HTTP 404).
type NotFoundError struct{ *APIError }

// ConflictError is returned when the request conflicts with the current state (HTTP 409).
type ConflictError struct{ *APIError }

// ValidationError is returned when request validation fails (HTTP 400/422).
type ValidationError struct{ *APIError }

// RateLimitError is returned when the rate limit is exceeded (HTTP 429).
type RateLimitError struct{ *APIError }

// NetworkError is returned when a transport-level (non-HTTP) error occurs.
type NetworkError struct {
	Message string
	Cause   error
}

func (e *NetworkError) Error() string {
	return fmt.Sprintf("apexmail: network error: %s", e.Message)
}

func (e *NetworkError) Unwrap() error { return e.Cause }

// EmailAddress represents a named email address.
type EmailAddress struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
}

// Priority named levels and their queue integers — the F48 shared contract
// (packages/contract/send-contract.json), identical to the API's mapping in
// api-server/src/routes/messages.rs (NAMED_PRIORITY_LEVELS). Every SDK
// serializes these exact forms, so a named level never yields a 422.
const (
	priorityNamedHigh   = "high"
	priorityNamedNormal = "normal"
	priorityNamedLow    = "low"
)

var (
	// PriorityHigh maps the named level "high" to queue integer 7.
	PriorityHigh = SendPriority{named: priorityNamedHigh, level: 7, set: true}
	// PriorityNormal maps the named level "normal" to queue integer 5.
	PriorityNormal = SendPriority{named: priorityNamedNormal, level: 5, set: true}
	// PriorityLow maps the named level "low" to queue integer 3.
	PriorityLow = SendPriority{named: priorityNamedLow, level: 3, set: true}
)

// PriorityInt returns a SendPriority for an integer queue level. The API
// accepts 1-10; any other integer is an error naming the contract.
func PriorityInt(level int) (SendPriority, error) {
	if level < 1 || level > 10 {
		return SendPriority{}, fmt.Errorf("apexmail: priority must be an integer between 1 and 10 or one of the named levels %q/%q/%q (got %d)",
			priorityNamedHigh, priorityNamedNormal, priorityNamedLow, level)
	}
	return SendPriority{level: level, set: true}, nil
}

// PriorityNamed returns a SendPriority for a documented named level
// ("high"/"normal"/"low", case-insensitive).
func PriorityNamed(level string) (SendPriority, error) {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case priorityNamedHigh:
		return PriorityHigh, nil
	case priorityNamedNormal:
		return PriorityNormal, nil
	case priorityNamedLow:
		return PriorityLow, nil
	default:
		return SendPriority{}, fmt.Errorf("apexmail: priority must be an integer between 1 and 10 or one of the named levels %q/%q/%q (got %q)",
			priorityNamedHigh, priorityNamedNormal, priorityNamedLow, level)
	}
}

// SendPriority is the send priority (F48 shared contract): an integer 1-10
// or one of the documented named levels "high"/"normal"/"low" (queue
// integers 7/5/3). It marshals to exactly the form the API accepts — the
// named string for named levels, a JSON number for integers — and
// unmarshals both forms (plus integers encoded as strings, for older
// integrations).
type SendPriority struct {
	named string
	level int
	set   bool
}

// IsZero reports whether no priority was set (the field is then omitted
// from the wire body entirely).
func (p SendPriority) IsZero() bool { return !p.set }

// QueueLevel returns the queue integer the API persists: 7/5/3 for the
// named levels, the integer itself otherwise.
func (p SendPriority) QueueLevel() int { return p.level }

// String renders the priority for logs and errors.
func (p SendPriority) String() string {
	if !p.set {
		return ""
	}
	if p.named != "" {
		return p.named
	}
	return strconv.Itoa(p.level)
}

// MarshalJSON serializes the exact wire form the API accepts (F48).
func (p SendPriority) MarshalJSON() ([]byte, error) {
	if !p.set {
		return []byte("null"), nil
	}
	if p.named != "" {
		return json.Marshal(p.named)
	}
	return json.Marshal(p.level)
}

// UnmarshalJSON accepts integers, the named levels, and integer strings.
func (p *SendPriority) UnmarshalJSON(data []byte) error {
	var asInt int
	if err := json.Unmarshal(data, &asInt); err == nil {
		normalized, err := PriorityInt(asInt)
		if err != nil {
			return err
		}
		*p = normalized
		return nil
	}
	var asString string
	if err := json.Unmarshal(data, &asString); err != nil {
		return fmt.Errorf("apexmail: priority must be an integer between 1 and 10 or one of the named levels %q/%q/%q",
			priorityNamedHigh, priorityNamedNormal, priorityNamedLow)
	}
	normalized, err := PriorityNamed(asString)
	if err != nil {
		return err
	}
	*p = normalized
	return nil
}

// Attachment represents an email attachment.
type Attachment struct {
	Filename    string `json:"filename"`
	Content     string `json:"content"`
	ContentType string `json:"contentType,omitempty"`
}

// Pagination holds list-response pagination metadata.
type Pagination struct {
	Total   int    `json:"total"`
	Limit   int    `json:"limit"`
	Offset  int    `json:"offset"`
	Cursor  string `json:"cursor,omitempty"`
	HasMore bool   `json:"hasMore"`
}

// EmailsAPI provides methods for sending and querying emails.
type EmailsAPI struct{ client *Client }

// SendEmailRequest is the request body for sending a single email.
//
// The wire payload (MarshalJSON) serializes every option the struct
// accepts (F48): from/to/cc/bcc/reply_to go out as address strings with
// display names preserved as RFC 5322 "Name <addr>" forms, tags as a
// string list, and reply_to, template_id/template_data, attachments and
// priority under their documented snake_case field names. Nothing the SDK
// accepts is dropped silently.
type SendEmailRequest struct {
	From         EmailAddress      `json:"from"`
	To           []EmailAddress    `json:"to"`
	CC           []EmailAddress    `json:"cc,omitempty"`
	BCC          []EmailAddress    `json:"bcc,omitempty"`
	ReplyTo      *EmailAddress     `json:"reply_to,omitempty"` // wire: display-name aware
	Subject      string            `json:"subject"`
	HTML         string            `json:"html,omitempty"`
	Text         string            `json:"text,omitempty"`
	TemplateID   string            `json:"template_id,omitempty"`   // wire: snake_case
	TemplateData interface{}       `json:"template_data,omitempty"` // wire: snake_case
	Attachments  []Attachment      `json:"attachments,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Priority     SendPriority      `json:"priority,omitempty"` // wire: int 1-10 or named level (F48 contract)
	Headers      map[string]string `json:"headers,omitempty"`
	ScheduledAt  string            `json:"scheduled_at,omitempty"` // wire: snake_case
	Metadata     interface{}       `json:"metadata,omitempty"`
}

// sendMessagePayload is the wire body for the messages send API. Every
// accepted option is serialized (F48) — display names survive as
// "Name <addr>" forms and extended options use their documented
// snake_case field names.
type sendMessagePayload struct {
	From         string            `json:"from"`
	To           []string          `json:"to"`
	CC           []string          `json:"cc,omitempty"`
	BCC          []string          `json:"bcc,omitempty"`
	ReplyTo      string            `json:"reply_to,omitempty"`
	Subject      string            `json:"subject"`
	HTML         string            `json:"html,omitempty"`
	Text         string            `json:"text,omitempty"`
	TemplateID   string            `json:"template_id,omitempty"`
	TemplateData interface{}       `json:"template_data,omitempty"`
	Attachments  []Attachment      `json:"attachments,omitempty"`
	Tags         []string          `json:"tags,omitempty"`
	Priority     *SendPriority     `json:"priority,omitempty"` // int 1-10 or named level, exactly as the API accepts (F48)
	Headers      map[string]string `json:"headers,omitempty"`
	Metadata     interface{}       `json:"metadata,omitempty"`
	ScheduledAt  string            `json:"scheduled_at,omitempty"`
}

// MarshalJSON serializes the send payload with every accepted option on
// the wire (F48).
func (r *SendEmailRequest) MarshalJSON() ([]byte, error) {
	payload := sendMessagePayload{
		From:         formatEmailAddress(r.From),
		To:           addressListToStrings(r.To),
		CC:           addressListToStrings(r.CC),
		BCC:          addressListToStrings(r.BCC),
		ReplyTo:      formatEmailAddressPtr(r.ReplyTo),
		Subject:      r.Subject,
		HTML:         r.HTML,
		Text:         r.Text,
		TemplateID:   r.TemplateID,
		TemplateData: r.TemplateData,
		Attachments:  r.Attachments,
		Tags:         r.Tags,
		Priority:     sendPriorityPtr(r.Priority),
		Headers:      r.Headers,
		Metadata:     r.Metadata,
		ScheduledAt:  r.ScheduledAt,
	}
	if payload.To == nil {
		payload.To = []string{}
	}
	return json.Marshal(payload)
}

// sendPriorityPtr keeps an unset priority OFF the wire entirely (omitting
// the field lets the server apply its default queue level of 5).
func sendPriorityPtr(p SendPriority) *SendPriority {
	if p.IsZero() {
		return nil
	}
	return &p
}

// formatEmailAddress serializes one address with its display name
// preserved: "Name <addr>" when a name is set, the bare address otherwise
// (F48).
func formatEmailAddress(address EmailAddress) string {
	if address.Name != "" && address.Email != "" {
		return address.Name + " <" + address.Email + ">"
	}
	return address.Email
}

func formatEmailAddressPtr(address *EmailAddress) string {
	if address == nil {
		return ""
	}
	return formatEmailAddress(*address)
}

// addressListToStrings serializes EmailAddress values to address strings,
// preserving display names as "Name <addr>" forms (F48).
func addressListToStrings(addresses []EmailAddress) []string {
	if len(addresses) == 0 {
		return nil
	}
	out := make([]string, 0, len(addresses))
	for _, address := range addresses {
		if address.Email != "" {
			out = append(out, formatEmailAddress(address))
		}
	}
	return out
}

// SendOptions configures optional behavior for Emails.Send.
type SendOptions struct {
	IdempotencyKey string
}

// SendEmailMessage contains details for a queued send (legacy nested shape).
//
// Deprecated: the API returns a flat {id, status, created_at} object; use the
// top-level SendEmailResponse fields instead.
type SendEmailMessage struct {
	ID          string `json:"id"`
	MessageID   string `json:"messageId"`
	Status      string `json:"status"`
	Recipients  int    `json:"recipients"`
	ScheduledAt string `json:"scheduledAt,omitempty"`
	CreatedAt   string `json:"createdAt"`
}

// SendEmailResponse is returned by Emails.Send. The real API (after envelope
// unwrap) is the flat object {"id": "...", "status": "...", "created_at": "..."}.
type SendEmailResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`

	// Deprecated: legacy nested shape kept only so old mock payloads still
	// decode. The live API never populates this field.
	Message SendEmailMessage `json:"message"`
}

// Send sends a single transactional email.
//
// When no IdempotencyKey is supplied in opts, a random UUID v4 is generated
// per logical send and replayed across transport retries of that send, so a
// retried POST can never enqueue the same message twice (SDK-B).
func (a *EmailsAPI) Send(ctx context.Context, req *SendEmailRequest, opts ...SendOptions) (*SendEmailResponse, error) {
	if err := validateSendEmailRequest(req); err != nil {
		return nil, err
	}
	var idempotencyKey string
	if len(opts) > 0 {
		idempotencyKey = opts[0].IdempotencyKey
	}
	if idempotencyKey == "" {
		key, err := newUUID4()
		if err != nil {
			return nil, err
		}
		idempotencyKey = key
	}
	var resp SendEmailResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/messages", req, &resp, idempotencyKey)
	return &resp, err
}

// BatchSendRequest is the request body for the batch send endpoint.
type BatchSendRequest struct {
	Messages []*SendEmailRequest `json:"messages"`
}

// BatchResultItem represents the outcome of a single email in a batch.
// Real API shape: {index, id (accepted only), status: "queued"|"rejected", error (rejected only)}.
type BatchResultItem struct {
	Index  int    `json:"index"`
	ID     string `json:"id,omitempty"`
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`

	// Deprecated legacy fields (never populated by the live API).
	Success   bool   `json:"success"`
	MessageID string `json:"messageId,omitempty"`
}

// BatchSummary contains aggregate batch statistics (legacy shape).
//
// Deprecated: the API returns top-level accepted/rejected counts instead.
type BatchSummary struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Failed  int `json:"failed"`
}

// BatchSendResponse is returned by Emails.Batch. The real API (after
// envelope unwrap) is {accepted, rejected, results: [{index, id?, status, error?}]}.
type BatchSendResponse struct {
	Accepted int               `json:"accepted"`
	Rejected int               `json:"rejected"`
	Results  []BatchResultItem `json:"results"`

	// Deprecated: legacy nested shape kept only so old mock payloads still
	// decode. The live API never populates this field.
	Summary BatchSummary `json:"summary"`
}

// Batch sends up to 1,000 emails in a single request.
//
// An idempotency key is generated automatically when not supplied in opts
// (SDK-B) and is replayed across transport retries of the batch call.
func (a *EmailsAPI) Batch(ctx context.Context, req *BatchSendRequest, opts ...SendOptions) (*BatchSendResponse, error) {
	if req == nil {
		return nil, fmt.Errorf("apexmail: batch request is required")
	}
	if len(req.Messages) == 0 {
		return nil, fmt.Errorf("apexmail: at least one message is required")
	}
	if len(req.Messages) > 1000 {
		return nil, fmt.Errorf("apexmail: batch limit exceeded (max 1000)")
	}
	for idx, message := range req.Messages {
		if err := validateSendEmailRequest(message); err != nil {
			return nil, fmt.Errorf("apexmail: batch message %d: %w", idx, err)
		}
	}
	var idempotencyKey string
	if len(opts) > 0 {
		idempotencyKey = opts[0].IdempotencyKey
	}
	if idempotencyKey == "" {
		key, err := newUUID4()
		if err != nil {
			return nil, err
		}
		idempotencyKey = key
	}
	var resp BatchSendResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/messages/batch", req, &resp, idempotencyKey)
	return &resp, err
}

// EmailDetail is the full email object returned by the API — the flat
// MessageDetail payload of GET /v1/messages/:id: {id, from (bare address
// string), to (string array), subject, status, tags, metadata,
// scheduled_at, sent_at, created_at}.
type EmailDetail struct {
	ID          string          `json:"id"`
	From        string          `json:"from"`
	To          []string        `json:"to"`
	Subject     string          `json:"subject"`
	Status      string          `json:"status"`
	Tags        []string        `json:"tags,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty"`
	ScheduledAt string          `json:"scheduled_at,omitempty"`
	CreatedAt   string          `json:"created_at"`
	SentAt      string          `json:"sent_at,omitempty"`
}

// GetEmailResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat MessageDetail object (no
// {"message": ...} wrapper); Get returns *EmailDetail directly.
type GetEmailResponse = EmailDetail

// Get retrieves an email by its ID (flat MessageDetail).
func (a *EmailsAPI) Get(ctx context.Context, id string) (*EmailDetail, error) {
	var resp EmailDetail
	err := a.client.do(ctx, http.MethodGet, "/v1/messages/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// MessageQueueResponse is returned by queue-oriented message actions
// ({id, status, created_at}).
type MessageQueueResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}

// Cancel stops a queued or scheduled email before delivery.
func (a *EmailsAPI) Cancel(ctx context.Context, id string) (*MessageQueueResponse, error) {
	if strings.TrimSpace(id) == "" {
		return nil, fmt.Errorf("apexmail: message id is required")
	}
	var resp MessageQueueResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/messages/"+url.PathEscape(id)+"/cancel", nil, &resp)
	return &resp, err
}

// ListEmailsOptions filters for the List endpoint. The server's
// ListMessagesQuery accepts {limit, offset, cursor, status, sort_by} only.
type ListEmailsOptions struct {
	Status string
	Limit  *int
	Offset int
	Cursor string
	Tag    string // Deprecated: not accepted by the API; not sent.
	SortBy string
}

// ListEmailsResponse holds a paginated list of emails. The API returns
// {"data": [MessageDetail...], "meta": {...}} — after envelope unwrap the
// payload is a bare array, which UnmarshalJSON accepts (as well as the
// historical {"messages": ...} object shape).
type ListEmailsResponse struct {
	Messages   []EmailDetail `json:"messages"`
	Pagination Pagination    `json:"pagination"`
}

// UnmarshalJSON accepts the API's bare array payload or the object form.
func (r *ListEmailsResponse) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &r.Messages)
	}
	type alias ListEmailsResponse
	return json.Unmarshal(trimmed, (*alias)(r))
}

// List retrieves a paginated list of emails for the tenant.
func (a *EmailsAPI) List(ctx context.Context, opts ...ListEmailsOptions) (*ListEmailsResponse, error) {
	var o ListEmailsOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	values := url.Values{}
	values.Set("limit", fmt.Sprintf("%d", optInt(o.Limit, 20)))
	values.Set("offset", fmt.Sprintf("%d", o.Offset))
	if o.Cursor != "" {
		values.Set("cursor", o.Cursor)
	}
	if o.Status != "" {
		values.Set("status", o.Status)
	}
	if o.SortBy != "" {
		values.Set("sort_by", o.SortBy)
	}
	query := "?" + values.Encode()
	var resp ListEmailsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/messages"+query, nil, &resp)
	return &resp, err
}

// DomainsAPI provides methods for managing sending domains.
type DomainsAPI struct{ client *Client }

// Domain matches the server's flat DomainResponse: {id, name, status,
// ses_verified, spf_verified, dkim_verified, dmarc_verified,
// return_path_verified, created_at}.
type Domain struct {
	ID                 string `json:"id"`
	Name               string `json:"name"`
	Status             string `json:"status"`
	SESVerified        bool   `json:"ses_verified"`
	SPFVerified        bool   `json:"spf_verified"`
	DKIMVerified       bool   `json:"dkim_verified"`
	DMARCVerified      bool   `json:"dmarc_verified"`
	ReturnPathVerified bool   `json:"return_path_verified"`
	CreatedAt          string `json:"created_at"`
}

// DNSRecord represents a single DNS record required for domain verification
// (domains.rs DnsRecord: {record_type, hostname, value, priority?}).
type DNSRecord struct {
	Type     string `json:"record_type"`
	Name     string `json:"hostname"`
	Value    string `json:"value"`
	Priority int    `json:"priority,omitempty"`
	Verified bool   `json:"verified,omitempty"`
}

// Envelope represents the SMTP delivery envelope with authentication results.
type Envelope struct {
	From      string   `json:"from"`
	To        []string `json:"to"`
	DKIM      string   `json:"dkim"`
	SPF       string   `json:"spf"`
	DMARC     string   `json:"dmarc"`
	Timestamp string   `json:"timestamp"`
}

// CreateDomainRequest is the request body for adding a new domain. The
// server's CreateDomainRequest accepts exactly {name} (deny_unknown_fields).
type CreateDomainRequest struct {
	Domain string `json:"name"`
}

// marshalCreateDomain emits the exact {name} wire shape regardless of the
// struct's field naming.
func (r *CreateDomainRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name string `json:"name"`
	}{Name: r.Domain})
}

// CreateDomainResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat DomainResponse; Create returns
// *Domain directly.
type CreateDomainResponse = Domain

// GetDomainResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat DomainResponse; Get returns *Domain
// directly.
type GetDomainResponse = Domain

// Create adds a new domain (body {name}) and returns the created domain.
func (a *DomainsAPI) Create(ctx context.Context, req *CreateDomainRequest) (*Domain, error) {
	var resp Domain
	err := a.client.do(ctx, http.MethodPost, "/v1/domains", req, &resp)
	return &resp, err
}

// Get retrieves a domain by its ID (flat DomainResponse).
func (a *DomainsAPI) Get(ctx context.Context, id string) (*Domain, error) {
	var resp Domain
	err := a.client.do(ctx, http.MethodGet, "/v1/domains/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// ListDomainsResponse holds a list of domains. The API returns a bare
// array (no envelope); UnmarshalJSON accepts both shapes.
type ListDomainsResponse struct {
	Domains    []Domain   `json:"domains"`
	Pagination Pagination `json:"pagination"`
}

// UnmarshalJSON accepts the API's bare array payload or the object form.
func (r *ListDomainsResponse) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &r.Domains)
	}
	type alias ListDomainsResponse
	return json.Unmarshal(trimmed, (*alias)(r))
}

// List retrieves all domains for the tenant.
func (a *DomainsAPI) List(ctx context.Context) (*ListDomainsResponse, error) {
	var resp ListDomainsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/domains", nil, &resp)
	return &resp, err
}

// VerifyDomainResponse matches the server's VerifyResponse: {domain,
// spf_verified, dkim_verified, dmarc_verified, return_path_verified, status}.
type VerifyDomainResponse struct {
	Domain             string `json:"domain"`
	SPFVerified        bool   `json:"spf_verified"`
	DKIMVerified       bool   `json:"dkim_verified"`
	DMARCVerified      bool   `json:"dmarc_verified"`
	ReturnPathVerified bool   `json:"return_path_verified"`
	Status             string `json:"status"`
}

// Verify triggers DNS verification for the given domain ID.
func (a *DomainsAPI) Verify(ctx context.Context, id string) (*VerifyDomainResponse, error) {
	var resp VerifyDomainResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/domains/"+url.PathEscape(id)+"/verify", nil, &resp)
	return &resp, err
}

// Delete removes a domain.
func (a *DomainsAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/domains/"+url.PathEscape(id), nil, nil)
}

// DomainHealthResponse is the historical health shape.
//
// Deprecated: the API has no GET /:id/health endpoint. GET /:id itself
// carries the health information (spf/dkim/dmarc/return_path verification
// booleans), so Health returns *Domain.
type DomainHealthResponse = Domain

// Health checks the deliverability health of a domain. The API has no
// /health subpath — this maps to GET /v1/domains/:id, whose
// DomainResponse contains the SPF/DKIM/DMARC/return-path verification
// state.
func (a *DomainsAPI) Health(ctx context.Context, id string) (*Domain, error) {
	return a.Get(ctx, id)
}

// WebhooksAPI provides methods for managing event webhooks.
type WebhooksAPI struct{ client *Client }

// KnownWebhookEvents lists the event names the server accepts
// (webhooks.rs KNOWN_WEBHOOK_EVENTS) — anything else is a 422.
var KnownWebhookEvents = []string{
	"email.delivered",
	"email.bounced",
	"email.complained",
	"message.sent",
	"message.delivered",
	"message.bounced",
	"message.complained",
	"message.opened",
	"message.clicked",
	"recipient.unsubscribed",
	"placement_test.completed",
	"bounce",
	"complaint",
	"inbound",
	"*",
}

// Webhook matches the server's flat WebhookResponse: {id, url, events,
// secret (only at creation/rotation), status, created_at, updated_at}.
// There is no name/enabled field — status is "active" | "paused" | "disabled".
type Webhook struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Secret    string   `json:"secret,omitempty"`
	Status    string   `json:"status"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

// CreateWebhookRequest is the request body for creating a webhook. The
// server's CreateWebhookRequest accepts exactly {url, events}
// (deny_unknown_fields); the signing secret is generated server-side and
// returned in the create response. Secret is accepted for backwards
// compatibility but NOT serialized.
type CreateWebhookRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret,omitempty"` // unused-input: not sent
}

// MarshalJSON emits the exact {url, events} wire shape.
func (r *CreateWebhookRequest) MarshalJSON() ([]byte, error) {
	events := r.Events
	if events == nil {
		events = []string{}
	}
	return json.Marshal(struct {
		URL    string   `json:"url"`
		Events []string `json:"events"`
	}{URL: r.URL, Events: events})
}

// CreateWebhookResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat WebhookResponse; Create returns
// *Webhook directly.
type CreateWebhookResponse = Webhook

// ListWebhooksResponse holds a list of webhooks. The API returns a bare
// array (no envelope); UnmarshalJSON accepts both shapes.
type ListWebhooksResponse struct {
	Webhooks []Webhook `json:"webhooks"`
}

// UnmarshalJSON accepts the API's bare array payload or the object form.
func (r *ListWebhooksResponse) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &r.Webhooks)
	}
	type alias ListWebhooksResponse
	return json.Unmarshal(trimmed, (*alias)(r))
}

// GetWebhookResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat WebhookResponse; Get returns *Webhook
// directly.
type GetWebhookResponse = Webhook

// Create registers a new webhook endpoint ({url, events} on the wire).
func (a *WebhooksAPI) Create(ctx context.Context, req *CreateWebhookRequest) (*Webhook, error) {
	var resp Webhook
	err := a.client.do(ctx, http.MethodPost, "/v1/webhooks", req, &resp)
	return &resp, err
}

// List retrieves all webhooks for the tenant.
func (a *WebhooksAPI) List(ctx context.Context) (*ListWebhooksResponse, error) {
	var resp ListWebhooksResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/webhooks", nil, &resp)
	return &resp, err
}

// Get retrieves a webhook by its ID (flat WebhookResponse).
func (a *WebhooksAPI) Get(ctx context.Context, id string) (*Webhook, error) {
	var resp Webhook
	err := a.client.do(ctx, http.MethodGet, "/v1/webhooks/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// UpdateWebhookRequest is the request body for updating a webhook. The
// server's UpdateWebhookRequest accepts {url?, events?, status?} with
// status one of "active" | "paused" | "disabled". Active (bool) is a
// backwards-compatible input mapped to status active/paused; Secret is not
// sent (secrets are server-managed via /rotate-secret).
type UpdateWebhookRequest struct {
	URL    string   `json:"url,omitempty"`
	Events []string `json:"events,omitempty"`
	Secret string   `json:"secret,omitempty"` // unused-input: not sent
	Active *bool    `json:"active,omitempty"` // mapped to status
	Status string   `json:"status,omitempty"` // "active" | "paused" | "disabled"
}

// MarshalJSON emits the exact {url, events, status} wire shape.
func (r *UpdateWebhookRequest) MarshalJSON() ([]byte, error) {
	status := r.Status
	if status == "" && r.Active != nil {
		if *r.Active {
			status = "active"
		} else {
			status = "paused"
		}
	}
	return json.Marshal(struct {
		URL    string   `json:"url,omitempty"`
		Events []string `json:"events,omitempty"`
		Status string   `json:"status,omitempty"`
	}{URL: r.URL, Events: r.Events, Status: status})
}

// UpdateWebhookResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat WebhookResponse; Update returns
// *Webhook directly.
type UpdateWebhookResponse = Webhook

// Update modifies a webhook's URL, event subscriptions, or status.
func (a *WebhooksAPI) Update(ctx context.Context, id string, req *UpdateWebhookRequest) (*Webhook, error) {
	var resp Webhook
	err := a.client.do(ctx, http.MethodPut, "/v1/webhooks/"+url.PathEscape(id), req, &resp)
	return &resp, err
}

// Delete removes a webhook.
func (a *WebhooksAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/webhooks/"+url.PathEscape(id), nil, nil)
}

// TestWebhookResponse matches the server's TestWebhookResponse: {success,
// status_code?, response_time_ms, error?}.
type TestWebhookResponse struct {
	Success        bool    `json:"success"`
	StatusCode     *uint16 `json:"status_code,omitempty"`
	ResponseTimeMs uint64  `json:"response_time_ms"`
	Error          string  `json:"error,omitempty"`
}

// Test sends a signed test event to a registered webhook endpoint. The
// server takes no body.
func (a *WebhooksAPI) Test(ctx context.Context, id string) (*TestWebhookResponse, error) {
	var resp TestWebhookResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/webhooks/"+url.PathEscape(id)+"/test", nil, &resp)
	return &resp, err
}

// RotateSecret rotates the webhook's signing secret and returns the
// webhook with the new secret (POST /v1/webhooks/:id/rotate-secret).
func (a *WebhooksAPI) RotateSecret(ctx context.Context, id string) (*Webhook, error) {
	var resp Webhook
	err := a.client.do(ctx, http.MethodPost, "/v1/webhooks/"+url.PathEscape(id)+"/rotate-secret", nil, &resp)
	return &resp, err
}

// TemplatesAPI provides methods for managing email templates.
type TemplatesAPI struct{ client *Client }

// Template matches the server's flat TemplateResponse: {id, name, subject,
// html_body, text_body, version, status, created_at, updated_at}.
type Template struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Subject   string `json:"subject"`
	HTMLBody  string `json:"html_body"`
	TextBody  string `json:"text_body,omitempty"`
	Version   int    `json:"version"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

// CreateTemplateRequest is the request body for creating a template. The
// server's CreateTemplateRequest accepts exactly {name, subject,
// html_body, text_body?} (deny_unknown_fields). The struct keeps its
// historical fields (HTML/Text/Slug/Engine/DefaultData) as inputs, but
// only the API-accepted subset is serialized.
type CreateTemplateRequest struct {
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug,omitempty"` // unused-input: not sent
	Subject     string                 `json:"subject"`
	HTML        string                 `json:"html_body"` // wire: html_body
	Text        string                 `json:"text_body,omitempty"`
	Engine      string                 `json:"engine,omitempty"`      // unused-input: not sent
	DefaultData map[string]interface{} `json:"defaultData,omitempty"` // unused-input: not sent
}

// MarshalJSON emits the exact {name, subject, html_body, text_body?} shape.
func (r *CreateTemplateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name     string `json:"name"`
		Subject  string `json:"subject"`
		HTMLBody string `json:"html_body"`
		TextBody string `json:"text_body,omitempty"`
	}{Name: r.Name, Subject: r.Subject, HTMLBody: r.HTML, TextBody: r.Text})
}

// CreateTemplateResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat TemplateResponse; Create returns
// *Template directly.
type CreateTemplateResponse = Template

// Create registers a new email template ({name, subject, html_body,
// text_body?} on the wire).
func (a *TemplatesAPI) Create(ctx context.Context, req *CreateTemplateRequest) (*Template, error) {
	var resp Template
	err := a.client.do(ctx, http.MethodPost, "/v1/templates", req, &resp)
	return &resp, err
}

// GetTemplateResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat TemplateResponse; Get returns
// *Template directly.
type GetTemplateResponse = Template

// Get retrieves a template by its ID (flat TemplateResponse).
func (a *TemplatesAPI) Get(ctx context.Context, id string) (*Template, error) {
	var resp Template
	err := a.client.do(ctx, http.MethodGet, "/v1/templates/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// ListTemplatesOptions filters for the Templates.List endpoint
// ({limit, offset, cursor} only on the server).
type ListTemplatesOptions struct {
	Limit  *int
	Offset int
	Cursor string
}

// ListTemplatesResponse holds a list of templates. The API returns a bare
// array (no envelope); UnmarshalJSON accepts both shapes.
type ListTemplatesResponse struct {
	Templates  []Template `json:"templates"`
	Pagination Pagination `json:"pagination"`
}

// UnmarshalJSON accepts the API's bare array payload or the object form.
func (r *ListTemplatesResponse) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &r.Templates)
	}
	type alias ListTemplatesResponse
	return json.Unmarshal(trimmed, (*alias)(r))
}

// List retrieves a paginated list of templates.
func (a *TemplatesAPI) List(ctx context.Context, opts ...ListTemplatesOptions) (*ListTemplatesResponse, error) {
	var o ListTemplatesOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	values := url.Values{}
	values.Set("limit", fmt.Sprintf("%d", optInt(o.Limit, 20)))
	values.Set("offset", fmt.Sprintf("%d", o.Offset))
	if o.Cursor != "" {
		values.Set("cursor", o.Cursor)
	}
	query := "?" + values.Encode()
	var resp ListTemplatesResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/templates"+query, nil, &resp)
	return &resp, err
}

// UpdateTemplateRequest is the request body for updating a template. The
// server's UpdateTemplateRequest accepts {name?, subject?, html_body?,
// text_body?}; legacy fields are kept as unused inputs.
type UpdateTemplateRequest struct {
	Name        string                 `json:"name,omitempty"`
	Subject     string                 `json:"subject,omitempty"`
	HTML        string                 `json:"html_body,omitempty"`
	Text        string                 `json:"text_body,omitempty"`
	Engine      string                 `json:"engine,omitempty"`      // unused-input: not sent
	DefaultData map[string]interface{} `json:"defaultData,omitempty"` // unused-input: not sent
}

// MarshalJSON emits the exact {name?, subject?, html_body?, text_body?} shape.
func (r *UpdateTemplateRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Name     string `json:"name,omitempty"`
		Subject  string `json:"subject,omitempty"`
		HTMLBody string `json:"html_body,omitempty"`
		TextBody string `json:"text_body,omitempty"`
	}{Name: r.Name, Subject: r.Subject, HTMLBody: r.HTML, TextBody: r.Text})
}

// UpdateTemplateResponse is the historical wrapper shape.
//
// Deprecated: the API returns the flat TemplateResponse; Update returns
// *Template directly.
type UpdateTemplateResponse = Template

// Update modifies a template. A new version is created automatically.
func (a *TemplatesAPI) Update(ctx context.Context, id string, req *UpdateTemplateRequest) (*Template, error) {
	var resp Template
	err := a.client.do(ctx, http.MethodPut, "/v1/templates/"+url.PathEscape(id), req, &resp)
	return &resp, err
}

// Duplicate creates a copy of a template with a new ID.
func (a *TemplatesAPI) Duplicate(ctx context.Context, id string) (*Template, error) {
	var resp Template
	err := a.client.do(ctx, http.MethodPost, "/v1/templates/"+url.PathEscape(id)+"/duplicate", nil, &resp)
	return &resp, err
}

// RollbackTemplateRequest is the request body for rolling back a template.
type RollbackTemplateRequest struct {
	Version int `json:"version"`
}

// Rollback rolls back a template to a previous version.
func (a *TemplatesAPI) Rollback(ctx context.Context, id string, version int) (*Template, error) {
	var resp Template
	err := a.client.do(ctx, http.MethodPost, "/v1/templates/"+url.PathEscape(id)+"/rollback",
		&RollbackTemplateRequest{Version: version}, &resp)
	return &resp, err
}

// Delete removes a template and all its versions.
func (a *TemplatesAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/templates/"+url.PathEscape(id), nil, nil)
}

// RenderTemplateRequest is the request body for rendering a template.
type RenderTemplateRequest struct {
	Variables map[string]interface{} `json:"variables"`
}

// RenderTemplateResponse is returned by Templates.Render
// ({subject, html, text?}).
type RenderTemplateResponse struct {
	HTML    string `json:"html"`
	Text    string `json:"text,omitempty"`
	Subject string `json:"subject"`
}

// Render renders a template with given data (dry-run, does not send).
func (a *TemplatesAPI) Render(ctx context.Context, id string, data map[string]interface{}) (*RenderTemplateResponse, error) {
	if data == nil {
		data = map[string]interface{}{}
	}
	var resp RenderTemplateResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/templates/"+url.PathEscape(id)+"/render", &RenderTemplateRequest{Variables: data}, &resp)
	return &resp, err
}

// SuppressionsAPI provides methods for managing the suppression list.
type SuppressionsAPI struct{ client *Client }

// AddSuppressionRequest adds email address(es) to the suppression list.
//
// The server's CreateSuppressionRequest accepts exactly {email: string,
// reason: string, source?: string} for ONE address (deny_unknown_fields —
// the historical emails[] body was rejected). A single entry POSTs one
// request; multiple entries use the /bulk endpoint with
// {entries: [{email, reason}]}.
type AddSuppressionRequest struct {
	Emails []string `json:"emails"`
	Reason string   `json:"reason"`
	Source string   `json:"source,omitempty"`
}

// createSuppressionPayload is the exact CreateSuppressionRequest wire shape.
type createSuppressionPayload struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
	Source string `json:"source,omitempty"`
}

// MarshalJSON emits the single-email wire shape when exactly one address
// is present (the common case). Multi-email requests are routed to Bulk
// by Add and never marshal through here.
func (r *AddSuppressionRequest) MarshalJSON() ([]byte, error) {
	email := ""
	if len(r.Emails) > 0 {
		email = r.Emails[0]
	}
	return json.Marshal(createSuppressionPayload{Email: email, Reason: r.Reason, Source: r.Source})
}

// BulkSuppressionEntry is one {email, reason} entry of a bulk request.
type BulkSuppressionEntry struct {
	Email  string `json:"email"`
	Reason string `json:"reason"`
}

// bulkSuppressionsWire is the exact BulkSuppressRequest wire shape.
type bulkSuppressionsWire struct {
	Entries []BulkSuppressionEntry `json:"entries"`
}

// BulkSuppressionsResponse matches the server's BulkSuppressResponse:
// {created, duplicates, invalid}.
type BulkSuppressionsResponse struct {
	Created    int `json:"created"`
	Duplicates int `json:"duplicates"`
	Invalid    int `json:"invalid"`
}

// Add adds one or more email addresses to the suppression list.
// reason should be "unsubscribe", "bounce", "complaint", or "manual".
// A single email POSTs {email, reason, source?}; multiple emails use the
// /v1/suppressions/bulk endpoint.
func (a *SuppressionsAPI) Add(ctx context.Context, req *AddSuppressionRequest) (*BulkSuppressionsResponse, error) {
	if req == nil || len(req.Emails) == 0 {
		return nil, fmt.Errorf("apexmail: at least one email is required")
	}
	if len(req.Emails) == 1 {
		err := a.client.do(ctx, http.MethodPost, "/v1/suppressions", req, nil)
		if err != nil {
			return nil, err
		}
		return &BulkSuppressionsResponse{Created: 1}, nil
	}

	entries := make([]BulkSuppressionEntry, 0, len(req.Emails))
	for _, email := range req.Emails {
		entries = append(entries, BulkSuppressionEntry{Email: email, Reason: req.Reason})
	}
	var resp BulkSuppressionsResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/suppressions/bulk", bulkSuppressionsWire{Entries: entries}, &resp)
	return &resp, err
}

// ListSuppressionsOptions filters for the Suppressions.List endpoint
// ({limit, offset, cursor, reason} only on the server).
type ListSuppressionsOptions struct {
	Reason string
	Limit  *int
	Offset int
	Cursor string
	Tag    string // Deprecated: not accepted by the API; not sent.
}

// Suppression matches the server's SuppressionResponse: {id, email,
// reason, source, created_at}.
type Suppression struct {
	ID        string `json:"id"`
	Email     string `json:"email"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	CreatedAt string `json:"created_at"`
}

// ListSuppressionsResponse holds a list of suppressed addresses. The API
// returns a bare array (no envelope); UnmarshalJSON accepts both shapes.
type ListSuppressionsResponse struct {
	Suppressions []Suppression `json:"suppressions"`
	Pagination   Pagination    `json:"pagination"`
}

// UnmarshalJSON accepts the API's bare array payload or the object form.
func (r *ListSuppressionsResponse) UnmarshalJSON(data []byte) error {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		return json.Unmarshal(trimmed, &r.Suppressions)
	}
	type alias ListSuppressionsResponse
	return json.Unmarshal(trimmed, (*alias)(r))
}

// List retrieves a paginated list of suppressed addresses.
func (a *SuppressionsAPI) List(ctx context.Context, opts ...ListSuppressionsOptions) (*ListSuppressionsResponse, error) {
	var o ListSuppressionsOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	values := url.Values{}
	values.Set("limit", fmt.Sprintf("%d", optInt(o.Limit, 50)))
	values.Set("offset", fmt.Sprintf("%d", o.Offset))
	if o.Cursor != "" {
		values.Set("cursor", o.Cursor)
	}
	if o.Reason != "" {
		values.Set("reason", o.Reason)
	}
	query := "?" + values.Encode()
	var resp ListSuppressionsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/suppressions"+query, nil, &resp)
	return &resp, err
}

// CheckSuppressionResponse matches the server's CheckResponse: {email,
// suppressed, reason?}.
type CheckSuppressionResponse struct {
	Email      string `json:"email"`
	Suppressed bool   `json:"suppressed"`
	Reason     string `json:"reason,omitempty"`
}

// Check whether a specific email address is on the suppression list.
func (a *SuppressionsAPI) Check(ctx context.Context, email string) (*CheckSuppressionResponse, error) {
	var resp CheckSuppressionResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/suppressions/check/"+url.PathEscape(email), nil, &resp)
	return &resp, err
}

// Delete removes a suppression entry by its ID.
func (a *SuppressionsAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/suppressions/"+url.PathEscape(id), nil, nil)
}

// BulkSuppressionsRequest is the request body for bulk suppression changes.
//
// Deprecated: use []BulkSuppressionEntry with BulkEntries — this legacy
// shape accepted arbitrary maps; the API's BulkEntry is exactly
// {email, reason} (deny_unknown_fields).
type BulkSuppressionsRequest = bulkSuppressionsWire

// Bulk adds suppressions through the API bulk endpoint
// ({entries: [{email, reason}]}).
func (a *SuppressionsAPI) Bulk(ctx context.Context, req *BulkSuppressionsRequest) (*BulkSuppressionsResponse, error) {
	return a.BulkEntries(ctx, req.Entries)
}

// BulkEntries adds suppressions in bulk with the exact BulkEntry shape.
func (a *SuppressionsAPI) BulkEntries(ctx context.Context, entries []BulkSuppressionEntry) (*BulkSuppressionsResponse, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("apexmail: at least one entry is required")
	}
	var resp BulkSuppressionsResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/suppressions/bulk", bulkSuppressionsWire{Entries: entries}, &resp)
	return &resp, err
}

// EventsAPI provides methods for querying email delivery events.
type EventsAPI struct{ client *Client }

// Event is the event resource.
type Event struct {
	ID        string `json:"id"`
	MessageID string `json:"messageId"`
	EventType string `json:"eventType"`
	Recipient string `json:"recipientEmail"`
	Timestamp string `json:"timestamp"`
}

// ListEventsOptions filters for the Events.List endpoint.
type ListEventsOptions struct {
	Type      string
	MessageID string
	DomainID  string
	Start     string
	End       string
	Limit     *int
	Offset    int
	Cursor    string
}

// ListEventsResponse holds a paginated list of events.
type ListEventsResponse struct {
	Events     []Event    `json:"events"`
	Pagination Pagination `json:"pagination"`
}

// List retrieves delivery events for the tenant with optional filters.
func (a *EventsAPI) List(ctx context.Context, opts ...ListEventsOptions) (*ListEventsResponse, error) {
	var o ListEventsOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	values := url.Values{}
	values.Set("limit", fmt.Sprintf("%d", optInt(o.Limit, 50)))
	values.Set("offset", fmt.Sprintf("%d", o.Offset))
	if o.Cursor != "" {
		values.Set("cursor", o.Cursor)
	}
	if o.Type != "" {
		values.Set("type", o.Type)
	}
	if o.MessageID != "" {
		values.Set("messageId", o.MessageID)
	}
	if o.DomainID != "" {
		values.Set("domainId", o.DomainID)
	}
	if o.Start != "" {
		values.Set("start", o.Start)
	}
	if o.End != "" {
		values.Set("end", o.End)
	}
	query := "?" + values.Encode()
	var resp ListEventsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/events"+query, nil, &resp)
	return &resp, err
}

// GetByMessage retrieves all events for a specific sent message.
func (a *EventsAPI) GetByMessage(ctx context.Context, messageID string) (*ListEventsResponse, error) {
	var resp ListEventsResponse
	values := url.Values{}
	values.Set("messageId", messageID)
	values.Set("limit", "100")
	err := a.client.do(ctx, http.MethodGet, "/v1/events?"+values.Encode(), nil, &resp)
	return &resp, err
}

// GetEventResponse wraps a single event resource.
type GetEventResponse struct {
	Event Event `json:"event"`
}

// Get retrieves a single event by its ID.
func (a *EventsAPI) Get(ctx context.Context, eventID string) (*GetEventResponse, error) {
	var resp GetEventResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/events/"+url.PathEscape(eventID), nil, &resp)
	return &resp, err
}

// EventAggregateOptions filters aggregate event queries.
type EventAggregateOptions struct {
	Type      string
	MessageID string
	DomainID  string
	Start     string
	End       string
	Interval  string
}

// EventAggregateResponse is a flexible aggregate event response payload.
type EventAggregateResponse map[string]interface{}

// Stats returns aggregate event counts with optional filters.
func (a *EventsAPI) Stats(ctx context.Context, opts ...EventAggregateOptions) (EventAggregateResponse, error) {
	path := "/v1/events/stats" + eventAggregateQuery(opts...)
	var resp EventAggregateResponse
	err := a.client.do(ctx, http.MethodGet, path, nil, &resp)
	return resp, err
}

// Timeseries returns event counts over time with optional filters.
func (a *EventsAPI) Timeseries(ctx context.Context, opts ...EventAggregateOptions) (EventAggregateResponse, error) {
	path := "/v1/events/timeseries" + eventAggregateQuery(opts...)
	var resp EventAggregateResponse
	err := a.client.do(ctx, http.MethodGet, path, nil, &resp)
	return resp, err
}

func eventAggregateQuery(opts ...EventAggregateOptions) string {
	if len(opts) == 0 {
		return ""
	}
	o := opts[0]
	values := url.Values{}
	if o.Type != "" {
		values.Set("type", o.Type)
	}
	if o.MessageID != "" {
		values.Set("messageId", o.MessageID)
	}
	if o.DomainID != "" {
		values.Set("domainId", o.DomainID)
	}
	if o.Start != "" {
		values.Set("start", o.Start)
	}
	if o.End != "" {
		values.Set("end", o.End)
	}
	if o.Interval != "" {
		values.Set("interval", o.Interval)
	}
	if encoded := values.Encode(); encoded != "" {
		return "?" + encoded
	}
	return ""
}

// APIKeysAPI provides API key management helpers.
type APIKeysAPI struct{ client *Client }

// CreateAPIKeyRequest is the request body for creating an API key. The
// server's CreateApiKeyRequest (auth.rs) accepts exactly {name,
// scopes: string[], expires_in_days?} — scopes is REQUIRED (use an empty
// slice for a key with no scopes). ExpiresAt is a legacy input and is not
// sent.
type CreateAPIKeyRequest struct {
	Name          string   `json:"name"`
	Scopes        []string `json:"scopes"`
	ExpiresInDays *int     `json:"expires_in_days,omitempty"`
	ExpiresAt     string   `json:"expiresAt,omitempty"` // unused-input: not sent
}

// MarshalJSON emits the exact {name, scopes, expires_in_days?} wire shape.
func (r *CreateAPIKeyRequest) MarshalJSON() ([]byte, error) {
	scopes := r.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	var expires *int
	if r.ExpiresInDays != nil {
		expires = r.ExpiresInDays
	}
	return json.Marshal(struct {
		Name          string   `json:"name"`
		Scopes        []string `json:"scopes"`
		ExpiresInDays *int     `json:"expires_in_days,omitempty"`
	}{Name: r.Name, Scopes: scopes, ExpiresInDays: expires})
}

// APIKeyResponse is a flexible API-key response payload. The real create
// response is {id, key, key_prefix, name, scopes, created_at, expires_at?}.
type APIKeyResponse map[string]interface{}

// ListAPIKeysOptions configures API key list pagination.
type ListAPIKeysOptions struct {
	Limit  int
	Offset int
	Cursor string
}

// ListAPIKeysResponse is a flexible API-key list response payload (the
// API returns a bare array of ApiKeyInfo objects).
type ListAPIKeysResponse map[string]interface{}

// Create creates a new API key ({name, scopes, expires_in_days?}).
func (a *APIKeysAPI) Create(ctx context.Context, req *CreateAPIKeyRequest) (APIKeyResponse, error) {
	if req == nil || strings.TrimSpace(req.Name) == "" {
		return nil, fmt.Errorf("apexmail: api key name is required")
	}
	var out APIKeyResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/auth/api-keys", req, &out)
	return out, err
}

// List returns API keys for the authenticated account.
func (a *APIKeysAPI) List(ctx context.Context, opts ...ListAPIKeysOptions) (ListAPIKeysResponse, error) {
	options := ListAPIKeysOptions{Limit: 50, Offset: 0}
	if len(opts) > 0 {
		options = opts[0]
		if options.Limit == 0 {
			options.Limit = 50
		}
	}
	query := url.Values{}
	query.Set("limit", strconv.Itoa(options.Limit))
	query.Set("offset", strconv.Itoa(options.Offset))
	if options.Cursor != "" {
		query.Set("cursor", options.Cursor)
	}
	var out ListAPIKeysResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/auth/api-keys?"+query.Encode(), nil, &out)
	return out, err
}

// Revoke revokes an API key by ID.
func (a *APIKeysAPI) Revoke(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/auth/api-keys/"+url.PathEscape(id), nil, nil)
}

// AnalyticsAPI provides aggregate analytics helpers.
//
// The analytics API exposes typed subpaths only (there is no GET
// /v1/analytics): /dashboard, /volume, /engagement, /deliverability,
// /subject-line (POST) and /export. Every GET subpath accepts exactly
// {from, to, interval} (interval: hour | day | week | month).
type AnalyticsAPI struct{ client *Client }

// AnalyticsOptions configures analytics queries.
type AnalyticsOptions struct {
	From     string
	To       string
	Interval string // hour | day | week | month
	// Deprecated legacy filters — not accepted by the API; not sent.
	GroupBy string // mapped to Interval by the deprecated Get
	Tag     string
	Domain  string
}

// AnalyticsResponse is a flexible analytics response payload.
type AnalyticsResponse map[string]interface{}

func (a *AnalyticsAPI) analyticsQuery(options AnalyticsOptions) (string, error) {
	interval := options.Interval
	if interval == "" && options.GroupBy != "" {
		interval = options.GroupBy
	}
	switch interval {
	case "", "hour", "day", "week", "month":
	default:
		return "", fmt.Errorf("apexmail: interval must be one of hour, day, week, month (got %q)", interval)
	}
	query := url.Values{}
	if options.From != "" {
		query.Set("from", options.From)
	}
	if options.To != "" {
		query.Set("to", options.To)
	}
	if interval != "" {
		query.Set("interval", interval)
	}
	if encoded := query.Encode(); encoded != "" {
		return "?" + encoded, nil
	}
	return "", nil
}

func (a *AnalyticsAPI) analyticsGet(ctx context.Context, subpath string, options AnalyticsOptions) (AnalyticsResponse, error) {
	query, err := a.analyticsQuery(options)
	if err != nil {
		return nil, err
	}
	var out AnalyticsResponse
	err = a.client.do(ctx, http.MethodGet, "/v1/analytics/"+subpath+query, nil, &out)
	return out, err
}

// Dashboard fetches dashboard counters: {total_sent, total_delivered,
// total_bounced, total_opened, total_clicked, delivery_rate, open_rate,
// click_rate}.
func (a *AnalyticsAPI) Dashboard(ctx context.Context, opts ...AnalyticsOptions) (AnalyticsResponse, error) {
	var options AnalyticsOptions
	if len(opts) > 0 {
		options = opts[0]
	}
	return a.analyticsGet(ctx, "dashboard", options)
}

// Volume fetches the volume timeseries: [{date, sent, delivered, bounced}].
func (a *AnalyticsAPI) Volume(ctx context.Context, opts ...AnalyticsOptions) (AnalyticsResponse, error) {
	var options AnalyticsOptions
	if len(opts) > 0 {
		options = opts[0]
	}
	return a.analyticsGet(ctx, "volume", options)
}

// Engagement fetches engagement rates plus a timeseries: {open_rate,
// click_rate, unsubscribe_rate, timeseries}.
func (a *AnalyticsAPI) Engagement(ctx context.Context, opts ...AnalyticsOptions) (AnalyticsResponse, error) {
	var options AnalyticsOptions
	if len(opts) > 0 {
		options = opts[0]
	}
	return a.analyticsGet(ctx, "engagement", options)
}

// Deliverability fetches deliverability rates: {delivery_rate,
// bounce_rate, complaint_rate, inbox_rate}.
func (a *AnalyticsAPI) Deliverability(ctx context.Context, opts ...AnalyticsOptions) (AnalyticsResponse, error) {
	var options AnalyticsOptions
	if len(opts) > 0 {
		options = opts[0]
	}
	return a.analyticsGet(ctx, "deliverability", options)
}

// SubjectLineResponse wraps the analyzer's score payload.
type SubjectLineResponse map[string]interface{}

// AnalyzeSubjectLine analyzes a subject line (POST /subject-line with body
// {subject}).
func (a *AnalyticsAPI) AnalyzeSubjectLine(ctx context.Context, subject string) (SubjectLineResponse, error) {
	if strings.TrimSpace(subject) == "" {
		return nil, fmt.Errorf("apexmail: subject is required")
	}
	var out SubjectLineResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/analytics/subject-line",
		struct {
			Subject string `json:"subject"`
		}{Subject: subject}, &out)
	return out, err
}

// ExportResponse matches the server's ExportResponse: {job_id?,
// download_url?, status}.
type ExportResponse struct {
	JobID       *string `json:"job_id"`
	DownloadURL *string `json:"download_url"`
	Status      string  `json:"status"`
}

// Export starts an analytics export job (GET /export with {from, to,
// format}).
func (a *AnalyticsAPI) Export(ctx context.Context, from, to, format string) (*ExportResponse, error) {
	if format == "" {
		format = "json"
	}
	query := url.Values{}
	query.Set("format", format)
	if from != "" {
		query.Set("from", from)
	}
	if to != "" {
		query.Set("to", to)
	}
	var out ExportResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/analytics/export?"+query.Encode(), nil, &out)
	return &out, err
}

// Get is the historical analytics entry point.
//
// Deprecated: GET /v1/analytics does not exist on the API. Use the typed
// subpath methods (Dashboard/Volume/Engagement/Deliverability). Kept as a
// thin alias of Dashboard for backwards compatibility; GroupBy is mapped
// to interval, Tag/Domain are ignored.
func (a *AnalyticsAPI) Get(ctx context.Context, opts ...AnalyticsOptions) (AnalyticsResponse, error) {
	return a.Dashboard(ctx, opts...)
}

func optInt(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}
