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
	defaultIdleConnTimeout       = 90 * time.Second
	defaultTLSHandshakeTimeout   = 10 * time.Second
	defaultMaxIdleConns          = 100
	defaultMaxIdleConnsPerHost   = 10
	defaultExpectContinueTimeout = 1 * time.Second
)

var apiKeyPattern = regexp.MustCompile(`^am_(live|test)_[A-Za-z0-9]{16,}$`)
var emailPattern = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)

// Client is the root ApexMail API client. Use New() to create one.
type Client struct {
	mu               sync.RWMutex
	apiKey           string
	apiKeyErr        error
	baseURL          string
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
func New(apiKey string, cfg ...Config) *Client {
	var c Config
	if len(cfg) > 0 {
		c = cfg[0]
	}
	baseURL := defaultBaseURL
	if c.BaseURL != "" {
		baseURL = c.BaseURL
	}
	if !strings.HasPrefix(baseURL, "https://") {
		panic("apexmail: baseURL must use HTTPS")
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
		httpClient:       httpClient,
		apiKeyErr:        validateAPIKey(apiKey),
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
	return cl
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
	if req.HTML == "" && req.Text == "" && req.TemplateID == "" {
		return fmt.Errorf("apexmail: html, text, or templateId is required")
	}
	return nil
}

func isValidEmailAddress(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if _, err := mail.ParseAddress(trimmed); err == nil {
		parts := strings.Split(trimmed, "@")
		if len(parts) == 2 {
			domain := strings.TrimSpace(parts[1])
			if strings.Contains(domain, ".") {
				return true
			}
		}
	}
	return emailPattern.MatchString(trimmed)
}

// WebhookSignatureOptions configures webhook signature verification.
type WebhookSignatureOptions struct {
	Payload   []byte
	Signature string
	Secret    string
	Timestamp string
	Tolerance time.Duration
}

// VerifyWebhookSignature validates a webhook payload signature using HMAC-SHA256.
func VerifyWebhookSignature(opts WebhookSignatureOptions) bool {
	if len(opts.Payload) == 0 || opts.Signature == "" || opts.Secret == "" {
		return false
	}

	timestamp, signature := parseWebhookSignature(opts.Signature)
	if opts.Timestamp != "" {
		timestamp = opts.Timestamp
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
	if absInt64(time.Now().Unix()-ts) > int64(opts.Tolerance.Seconds()) {
		return false
	}

	signedPayload := fmt.Sprintf("%d.%s", ts, opts.Payload)
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
	c.mu.RUnlock()

	if apiKeyErr != nil {
		return apiKeyErr
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
		req, err := http.NewRequestWithContext(ctx, method, baseURL+path, bodyReader)
		if err != nil {
			return &NetworkError{Message: "create request: " + err.Error(), Cause: err}
		}
		req.Header.Set("X-API-Key", apiKey)
		req.Header.Set("User-Agent", "apexmail-go/"+sdkVersion)
		if bodyReader != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if len(idempotencyKey) > 0 && idempotencyKey[0] != "" {
			req.Header.Set("X-Idempotency-Key", idempotencyKey[0])
		}

		resp, err := httpClient.Do(req)
		if err != nil {
			if attempt < defaultMaxRetries {
				if sleepErr := sleepWithContext(ctx, calculateBackoff(attempt)); sleepErr != nil {
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
				if sleepErr := sleepWithContext(ctx, retryDelay(resp, attempt)); sleepErr != nil {
					return &NetworkError{Message: "request canceled", Cause: sleepErr}
				}
				continue
			}
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

func retryDelay(resp *http.Response, attempt int) time.Duration {
	retryAfter := resp.Header.Get("Retry-After")
	if retryAfter == "" {
		return calculateBackoff(attempt)
	}
	if seconds, err := strconv.Atoi(retryAfter); err == nil {
		delay := time.Duration(seconds) * time.Second
		if delay > defaultMaxBackoff {
			return defaultMaxBackoff
		}
		return delay
	}
	if t, err := time.Parse(time.RFC1123, retryAfter); err == nil {
		delay := time.Until(t)
		if delay < 0 {
			return 0
		}
		if delay > defaultMaxBackoff {
			return defaultMaxBackoff
		}
		return delay
	}
	if t, err := time.Parse(time.RFC1123Z, retryAfter); err == nil {
		delay := time.Until(t)
		if delay < 0 {
			return 0
		}
		if delay > defaultMaxBackoff {
			return defaultMaxBackoff
		}
		return delay
	}
	return calculateBackoff(attempt)
}

func calculateBackoff(attempt int) time.Duration {
	if attempt < 0 {
		attempt = 0
	}
	if attempt > 20 {
		attempt = 20
	}
	delay := defaultInitialBackoff * time.Duration(1<<uint(attempt))
	if delay > defaultMaxBackoff {
		return defaultMaxBackoff
	}
	return delay
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
	if _, exists := dataObject["pagination"]; exists {
		return data
	}

	var metaObject map[string]json.RawMessage
	if err := json.Unmarshal(meta, &metaObject); err == nil && metaObject != nil {
		if pagination, ok := metaObject["pagination"]; ok {
			dataObject["pagination"] = pagination
		} else {
			dataObject["pagination"] = meta
		}
	} else {
		dataObject["pagination"] = meta
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
	case err.StatusCode == http.StatusNotFound || err.Code == "NOT_FOUND":
		return &NotFoundError{APIError: err}
	case err.Code == "VALIDATION_ERROR" || err.Code == "INVALID_INPUT" || err.StatusCode == http.StatusUnprocessableEntity:
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

// NotFoundError is returned when the requested resource does not exist (HTTP 404).
type NotFoundError struct{ *APIError }

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

// Attachment represents an email attachment.
type Attachment struct {
	Filename    string `json:"filename"`
	Content     string `json:"content"`
	ContentType string `json:"contentType,omitempty"`
}

// Pagination holds list-response pagination metadata.
type Pagination struct {
	Total   int  `json:"total"`
	Limit   int  `json:"limit"`
	Offset  int  `json:"offset"`
	HasMore bool `json:"hasMore"`
}

// EmailsAPI provides methods for sending and querying emails.
type EmailsAPI struct{ client *Client }

// SendEmailRequest is the request body for sending a single email.
type SendEmailRequest struct {
	From         EmailAddress   `json:"from"`
	To           []EmailAddress `json:"to"`
	CC           []EmailAddress `json:"cc,omitempty"`
	BCC          []EmailAddress `json:"bcc,omitempty"`
	ReplyTo      *EmailAddress  `json:"replyTo,omitempty"`
	Subject      string         `json:"subject"`
	HTML         string         `json:"html,omitempty"`
	Text         string         `json:"text,omitempty"`
	TemplateID   string         `json:"templateId,omitempty"`
	TemplateData interface{}    `json:"templateData,omitempty"`
	Attachments  []Attachment   `json:"attachments,omitempty"`
	Tags         []string       `json:"tags,omitempty"`
	Priority     string         `json:"priority,omitempty"`
	ScheduledAt  string         `json:"scheduledAt,omitempty"`
	Metadata     interface{}    `json:"metadata,omitempty"`
}

// SendOptions configures optional behavior for Emails.Send.
type SendOptions struct {
	IdempotencyKey string
}

// SendEmailMessage contains details for a queued send.
type SendEmailMessage struct {
	ID          string `json:"id"`
	MessageID   string `json:"messageId"`
	Status      string `json:"status"`
	Recipients  int    `json:"recipients"`
	ScheduledAt string `json:"scheduledAt,omitempty"`
	CreatedAt   string `json:"createdAt"`
}

// SendEmailResponse is returned by Emails.Send.
type SendEmailResponse struct {
	Message SendEmailMessage `json:"message"`
}

// Send sends a single transactional email.
func (a *EmailsAPI) Send(ctx context.Context, req *SendEmailRequest, opts ...SendOptions) (*SendEmailResponse, error) {
	if err := validateSendEmailRequest(req); err != nil {
		return nil, err
	}
	var idempotencyKey string
	if len(opts) > 0 {
		idempotencyKey = opts[0].IdempotencyKey
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
type BatchResultItem struct {
	Index     int    `json:"index"`
	Success   bool   `json:"success"`
	MessageID string `json:"messageId,omitempty"`
	Error     string `json:"error,omitempty"`
}

// BatchSummary contains aggregate batch statistics.
type BatchSummary struct {
	Total   int `json:"total"`
	Success int `json:"success"`
	Failed  int `json:"failed"`
}

// BatchSendResponse is returned by Emails.Batch.
type BatchSendResponse struct {
	Results []BatchResultItem `json:"results"`
	Summary BatchSummary      `json:"summary"`
}

// Batch sends up to 1,000 emails in a single request.
func (a *EmailsAPI) Batch(ctx context.Context, req *BatchSendRequest) (*BatchSendResponse, error) {
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
	var resp BatchSendResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/messages/batch", req, &resp)
	return &resp, err
}

// EmailDetail is the full email object returned by the API.
type EmailDetail struct {
	ID          string   `json:"id"`
	Status      string   `json:"status"`
	From        string   `json:"fromEmail"`
	Subject     string   `json:"subject"`
	Tags        []string `json:"tags"`
	CreatedAt   string   `json:"createdAt"`
	SentAt      string   `json:"sentAt,omitempty"`
	DeliveredAt string   `json:"deliveredAt,omitempty"`
	OpenedAt    string   `json:"openedAt,omitempty"`
	ClickedAt   string   `json:"clickedAt,omitempty"`
}

// GetEmailResponse wraps a single email resource.
type GetEmailResponse struct {
	Message EmailDetail `json:"message"`
}

// Get retrieves an email by its ID.
func (a *EmailsAPI) Get(ctx context.Context, id string) (*GetEmailResponse, error) {
	var resp GetEmailResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/messages/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// MessageQueueResponse is returned by queue-oriented message actions.
type MessageQueueResponse struct {
	ID        string `json:"id"`
	Status    string `json:"status"`
	CreatedAt string `json:"createdAt"`
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

// ListEmailsOptions filters for the List endpoint.
type ListEmailsOptions struct {
	Status string
	Limit  *int
	Offset int
	Tag    string
}

// ListEmailsResponse holds a paginated list of emails.
type ListEmailsResponse struct {
	Messages   []EmailDetail `json:"messages"`
	Pagination Pagination    `json:"pagination"`
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
	if o.Status != "" {
		values.Set("status", o.Status)
	}
	if o.Tag != "" {
		values.Set("tag", o.Tag)
	}
	query := "?" + values.Encode()
	var resp ListEmailsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/messages"+query, nil, &resp)
	return &resp, err
}

// DomainsAPI provides methods for managing sending domains.
type DomainsAPI struct{ client *Client }

// Domain is the domain resource.
type Domain struct {
	ID           string `json:"id"`
	Domain       string `json:"domain"`
	Status       string `json:"status"`
	HealthStatus string `json:"healthStatus"`
	VerifiedAt   string `json:"verifiedAt,omitempty"`
	CreatedAt    string `json:"createdAt"`
}

// DNSRecord represents a single DNS record required for domain verification.
type DNSRecord struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Value    string `json:"value"`
	Priority int    `json:"priority,omitempty"`
	Verified bool   `json:"verified"`
}

// CreateDomainRequest is the request body for adding a new domain.
type CreateDomainRequest struct {
	Domain string `json:"domain"`
}

// CreateDomainResponse wraps the newly created domain.
type CreateDomainResponse struct {
	Domain     Domain      `json:"domain"`
	DNSRecords []DNSRecord `json:"dnsRecords"`
}

// GetDomainResponse wraps a single domain.
type GetDomainResponse struct {
	Domain Domain `json:"domain"`
}

// Create adds a new domain and returns the DNS records to configure.
func (a *DomainsAPI) Create(ctx context.Context, req *CreateDomainRequest) (*CreateDomainResponse, error) {
	var resp CreateDomainResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/domains", req, &resp)
	return &resp, err
}

// Get retrieves a domain by its ID.
func (a *DomainsAPI) Get(ctx context.Context, id string) (*GetDomainResponse, error) {
	var resp GetDomainResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/domains/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// ListDomainsResponse holds a paginated list of domains.
type ListDomainsResponse struct {
	Domains    []Domain   `json:"domains"`
	Pagination Pagination `json:"pagination"`
}

// List retrieves all domains for the tenant.
func (a *DomainsAPI) List(ctx context.Context) (*ListDomainsResponse, error) {
	var resp ListDomainsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/domains", nil, &resp)
	return &resp, err
}

// VerifyDomainResponse is returned by DomainsAPI.Verify.
type VerifyDomainResponse struct {
	Verified bool   `json:"verified"`
	Message  string `json:"message"`
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

// DomainHealthResponse contains SPF/DKIM/DMARC/blacklist status.
type DomainHealthResponse struct {
	SPF       string `json:"spf"`
	DKIM      string `json:"dkim"`
	DMARC     string `json:"dmarc"`
	Blacklist string `json:"blacklist"`
	Healthy   bool   `json:"healthy"`
}

// Health checks the deliverability health of a domain (SPF/DKIM/DMARC/blacklist).
func (a *DomainsAPI) Health(ctx context.Context, id string) (*DomainHealthResponse, error) {
	var resp DomainHealthResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/domains/"+url.PathEscape(id)+"/health", nil, &resp)
	return &resp, err
}

// WebhooksAPI provides methods for managing event webhooks.
type WebhooksAPI struct{ client *Client }

// Webhook is the webhook resource.
type Webhook struct {
	ID        string   `json:"id"`
	URL       string   `json:"url"`
	Events    []string `json:"events"`
	Active    bool     `json:"active"`
	CreatedAt string   `json:"createdAt"`
}

// CreateWebhookRequest is the request body for creating a webhook.
type CreateWebhookRequest struct {
	URL    string   `json:"url"`
	Events []string `json:"events"`
	Secret string   `json:"secret,omitempty"`
}

// CreateWebhookResponse wraps a created webhook.
type CreateWebhookResponse struct {
	Webhook Webhook `json:"webhook"`
}

// ListWebhooksResponse wraps a list of webhooks.
type ListWebhooksResponse struct {
	Webhooks []Webhook `json:"webhooks"`
}

// GetWebhookResponse wraps a single webhook.
type GetWebhookResponse struct {
	Webhook Webhook `json:"webhook"`
}

// Create registers a new webhook endpoint.
func (a *WebhooksAPI) Create(ctx context.Context, req *CreateWebhookRequest) (*CreateWebhookResponse, error) {
	var resp CreateWebhookResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/webhooks", req, &resp)
	return &resp, err
}

// List retrieves all webhooks for the tenant.
func (a *WebhooksAPI) List(ctx context.Context) (*ListWebhooksResponse, error) {
	var resp ListWebhooksResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/webhooks", nil, &resp)
	return &resp, err
}

// Get retrieves a webhook by its ID.
func (a *WebhooksAPI) Get(ctx context.Context, id string) (*GetWebhookResponse, error) {
	var resp GetWebhookResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/webhooks/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// UpdateWebhookRequest is the request body for updating a webhook.
type UpdateWebhookRequest struct {
	URL    string   `json:"url,omitempty"`
	Events []string `json:"events,omitempty"`
	Secret string   `json:"secret,omitempty"`
	Active *bool    `json:"active,omitempty"`
}

// UpdateWebhookResponse wraps an updated webhook.
type UpdateWebhookResponse struct {
	Webhook Webhook `json:"webhook"`
}

// Update modifies a webhook's URL, event subscriptions, or active status.
func (a *WebhooksAPI) Update(ctx context.Context, id string, req *UpdateWebhookRequest) (*UpdateWebhookResponse, error) {
	var resp UpdateWebhookResponse
	err := a.client.do(ctx, http.MethodPatch, "/v1/webhooks/"+url.PathEscape(id), req, &resp)
	return &resp, err
}

// Delete removes a webhook.
func (a *WebhooksAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/webhooks/"+url.PathEscape(id), nil, nil)
}

// TemplatesAPI provides methods for managing email templates.
type TemplatesAPI struct{ client *Client }

// Template is the template resource.
type Template struct {
	ID             string `json:"id"`
	Name           string `json:"name"`
	Slug           string `json:"slug"`
	Subject        string `json:"subject"`
	Engine         string `json:"engine"`
	CurrentVersion int    `json:"currentVersion"`
	IsActive       bool   `json:"isActive"`
	CreatedAt      string `json:"createdAt"`
	UpdatedAt      string `json:"updatedAt"`
}

// CreateTemplateRequest is the request body for creating a template.
type CreateTemplateRequest struct {
	Name        string                 `json:"name"`
	Slug        string                 `json:"slug,omitempty"`
	Subject     string                 `json:"subject"`
	HTML        string                 `json:"html,omitempty"`
	Text        string                 `json:"text,omitempty"`
	Engine      string                 `json:"engine,omitempty"`
	DefaultData map[string]interface{} `json:"defaultData,omitempty"`
}

// CreateTemplateResponse wraps a created template.
type CreateTemplateResponse struct {
	Template Template `json:"template"`
}

// Create registers a new email template.
func (a *TemplatesAPI) Create(ctx context.Context, req *CreateTemplateRequest) (*CreateTemplateResponse, error) {
	var resp CreateTemplateResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/templates", req, &resp)
	return &resp, err
}

// GetTemplateResponse wraps a template.
type GetTemplateResponse struct {
	Template Template `json:"template"`
}

// Get retrieves a template by its ID.
func (a *TemplatesAPI) Get(ctx context.Context, id string) (*GetTemplateResponse, error) {
	var resp GetTemplateResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/templates/"+url.PathEscape(id), nil, &resp)
	return &resp, err
}

// GetTemplateBySlugResponse wraps a template fetched by slug.
type GetTemplateBySlugResponse struct {
	Template Template `json:"template"`
}

// GetBySlug retrieves a template by its unique slug.
func (a *TemplatesAPI) GetBySlug(ctx context.Context, slug string) (*GetTemplateBySlugResponse, error) {
	var resp GetTemplateBySlugResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/templates/slug/"+url.PathEscape(slug), nil, &resp)
	return &resp, err
}

// ListTemplatesOptions filters for the Templates.List endpoint.
type ListTemplatesOptions struct {
	Limit  *int
	Offset int
}

// ListTemplatesResponse holds a paginated list of templates.
type ListTemplatesResponse struct {
	Templates  []Template `json:"templates"`
	Pagination Pagination `json:"pagination"`
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
	query := "?" + values.Encode()
	var resp ListTemplatesResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/templates"+query, nil, &resp)
	return &resp, err
}

// UpdateTemplateRequest is the request body for updating a template.
type UpdateTemplateRequest struct {
	Name        string                 `json:"name,omitempty"`
	Subject     string                 `json:"subject,omitempty"`
	HTML        string                 `json:"html,omitempty"`
	Text        string                 `json:"text,omitempty"`
	Engine      string                 `json:"engine,omitempty"`
	DefaultData map[string]interface{} `json:"defaultData,omitempty"`
}

// UpdateTemplateResponse wraps an updated template.
type UpdateTemplateResponse struct {
	Template Template `json:"template"`
}

// Update modifies a template. A new version is created automatically.
func (a *TemplatesAPI) Update(ctx context.Context, id string, req *UpdateTemplateRequest) (*UpdateTemplateResponse, error) {
	var resp UpdateTemplateResponse
	err := a.client.do(ctx, http.MethodPatch, "/v1/templates/"+url.PathEscape(id), req, &resp)
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

// RenderTemplateResponse is returned by Templates.Render.
type RenderTemplateResponse struct {
	HTML    string `json:"html"`
	Text    string `json:"text"`
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

// AddSuppressionRequest adds one or more emails to the suppression list.
type AddSuppressionRequest struct {
	Emails []string `json:"emails"`
	Reason string   `json:"reason"`
}

// Add adds one or more email addresses to the suppression list.
// reason should be "unsubscribe", "bounce", "complaint", or "manual".
func (a *SuppressionsAPI) Add(ctx context.Context, req *AddSuppressionRequest) error {
	return a.client.do(ctx, http.MethodPost, "/v1/suppressions", req, nil)
}

// ListSuppressionsOptions filters for the Suppressions.List endpoint.
type ListSuppressionsOptions struct {
	Reason string
	Limit  *int
	Offset int
}

// Suppression is a suppressed email address record.
type Suppression struct {
	Email     string `json:"email"`
	Reason    string `json:"reason"`
	CreatedAt string `json:"createdAt"`
}

// ListSuppressionsResponse holds a paginated list of suppressed addresses.
type ListSuppressionsResponse struct {
	Suppressions []Suppression `json:"suppressions"`
	Pagination   Pagination    `json:"pagination"`
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
	if o.Reason != "" {
		values.Set("reason", o.Reason)
	}
	query := "?" + values.Encode()
	var resp ListSuppressionsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/suppressions"+query, nil, &resp)
	return &resp, err
}

// CheckSuppressionResponse indicates whether an email address is suppressed.
type CheckSuppressionResponse struct {
	Suppressed bool   `json:"suppressed"`
	Reason     string `json:"reason,omitempty"`
	CreatedAt  string `json:"createdAt,omitempty"`
}

// Check whether a specific email address is on the suppression list.
func (a *SuppressionsAPI) Check(ctx context.Context, email string) (*CheckSuppressionResponse, error) {
	var resp CheckSuppressionResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/suppressions/check/"+url.PathEscape(email), nil, &resp)
	return &resp, err
}

// Delete removes an email from the suppression list.
func (a *SuppressionsAPI) Delete(ctx context.Context, email string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/suppressions/"+url.PathEscape(email), nil, nil)
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

// APIKeysAPI provides API key management helpers.
type APIKeysAPI struct{ client *Client }

// CreateAPIKeyRequest is the request body for creating an API key.
type CreateAPIKeyRequest struct {
	Name      string `json:"name"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// APIKeyResponse is a flexible API-key response payload.
type APIKeyResponse map[string]interface{}

// ListAPIKeysOptions configures API key list pagination.
type ListAPIKeysOptions struct {
	Limit  int
	Offset int
}

// ListAPIKeysResponse is a flexible API-key list response payload.
type ListAPIKeysResponse map[string]interface{}

// Create creates a new API key.
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
	var out ListAPIKeysResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/auth/api-keys?"+query.Encode(), nil, &out)
	return out, err
}

// Revoke revokes an API key by ID.
func (a *APIKeysAPI) Revoke(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/auth/api-keys/"+url.PathEscape(id), nil, nil)
}

// AnalyticsAPI provides aggregate analytics helpers.
type AnalyticsAPI struct{ client *Client }

// AnalyticsOptions configures analytics queries.
type AnalyticsOptions struct {
	From    string
	To      string
	GroupBy string
	Tag     string
}

// AnalyticsResponse is a flexible analytics response payload.
type AnalyticsResponse map[string]interface{}

// Get fetches analytics with optional filters.
func (a *AnalyticsAPI) Get(ctx context.Context, opts ...AnalyticsOptions) (AnalyticsResponse, error) {
	var options AnalyticsOptions
	if len(opts) > 0 {
		options = opts[0]
	}
	query := url.Values{}
	if options.From != "" {
		query.Set("from", options.From)
	}
	if options.To != "" {
		query.Set("to", options.To)
	}
	if options.GroupBy != "" {
		query.Set("groupBy", options.GroupBy)
	}
	if options.Tag != "" {
		query.Set("tag", options.Tag)
	}
	path := "/v1/analytics"
	if encoded := query.Encode(); encoded != "" {
		path += "?" + encoded
	}
	var out AnalyticsResponse
	err := a.client.do(ctx, http.MethodGet, path, nil, &out)
	return out, err
}

func optInt(v *int, def int) int {
	if v == nil {
		return def
	}
	return *v
}
