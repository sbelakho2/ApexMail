// Package apexmail is the official Go SDK for the ApexMail transactional email API.
//
// Usage:
//
//	client := apexmail.New("am_live_xxxx")
//	resp, err := client.Emails.Send(ctx, &apexmail.SendEmailRequest{
//	    From:    "hello@example.com",
//	    To:      []string{"user@example.com"},
//	    Subject: "Hello!",
//	    HTML:    "<h1>Hello World</h1>",
//	})
package apexmail

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	defaultBaseURL = "https://api.apexmail.ee"
	defaultTimeout = 30 * time.Second
	sdkVersion     = "1.0.0"
)

// Client is the root ApexMail API client. Use New() to create one.
type Client struct {
	apiKey       string
	baseURL      string
	httpClient   *http.Client
	Emails       *EmailsAPI
	Domains      *DomainsAPI
	Webhooks     *WebhooksAPI
	Templates    *TemplatesAPI
	Suppressions *SuppressionsAPI
	Events       *EventsAPI
}

// Config holds optional configuration for the client.
type Config struct {
	BaseURL    string
	HTTPClient *http.Client
	Timeout    time.Duration
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
	timeout := defaultTimeout
	if c.Timeout > 0 {
		timeout = c.Timeout
	}
	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: timeout}
	}
	cl := &Client{
		apiKey:     apiKey,
		baseURL:    baseURL,
		httpClient: httpClient,
	}
	cl.Emails = &EmailsAPI{client: cl}
	cl.Domains = &DomainsAPI{client: cl}
	cl.Webhooks = &WebhooksAPI{client: cl}
	cl.Templates = &TemplatesAPI{client: cl}
	cl.Suppressions = &SuppressionsAPI{client: cl}
	cl.Events = &EventsAPI{client: cl}
	return cl
}

func (c *Client) do(ctx context.Context, method, path string, body, out interface{}, idempotencyKey ...string) error {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("apexmail: marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, bodyReader)
	if err != nil {
		return &NetworkError{Message: "create request: " + err.Error(), Cause: err}
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "apexmail-go/"+sdkVersion)
	if len(idempotencyKey) > 0 && idempotencyKey[0] != "" {
		req.Header.Set("X-Idempotency-Key", idempotencyKey[0])
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return &NetworkError{Message: err.Error(), Cause: err}
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &NetworkError{Message: "read response body: " + err.Error(), Cause: err}
	}
	if resp.StatusCode >= 400 {
		var apiErr APIError
		if jsonErr := json.Unmarshal(respBody, &apiErr); jsonErr != nil {
			apiErr.Message = fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(respBody))
		}
		apiErr.StatusCode = resp.StatusCode
		switch resp.StatusCode {
		case 401:
			return &AuthenticationError{APIError: apiErr}
		case 404:
			return &NotFoundError{APIError: apiErr}
		case 422:
			return &ValidationError{APIError: apiErr}
		case 429:
			return &RateLimitError{APIError: apiErr}
		default:
			return &apiErr
		}
	}
	if out != nil && len(respBody) > 0 {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("apexmail: unmarshal response: %w", err)
		}
	}
	return nil
}

// APIError represents an error response from the ApexMail API.
type APIError struct {
	StatusCode int
	Message    string `json:"error"`
	Code       string `json:"code"`
}

func (e *APIError) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("apexmail: %s (code: %s, status: %d)", e.Message, e.Code, e.StatusCode)
	}
	return fmt.Sprintf("apexmail: %s (status: %d)", e.Message, e.StatusCode)
}

// Typed error subtypes for specific HTTP status codes.

// AuthenticationError is returned when the API key is missing, invalid, or revoked (HTTP 401).
type AuthenticationError struct{ APIError }

// NotFoundError is returned when the requested resource does not exist (HTTP 404).
type NotFoundError struct{ APIError }

// ValidationError is returned when request validation fails (HTTP 422).
type ValidationError struct{ APIError }

// RateLimitError is returned when the rate limit is exceeded (HTTP 429).
type RateLimitError struct{ APIError }

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
	From           interface{}  `json:"from"`
	To             interface{}  `json:"to"`
	CC             interface{}  `json:"cc,omitempty"`
	BCC            interface{}  `json:"bcc,omitempty"`
	ReplyTo        string       `json:"replyTo,omitempty"`
	Subject        string       `json:"subject"`
	HTML           string       `json:"html,omitempty"`
	Text           string       `json:"text,omitempty"`
	TemplateID     string       `json:"templateId,omitempty"`
	TemplateData   interface{}  `json:"templateData,omitempty"`
	Attachments    []Attachment `json:"attachments,omitempty"`
	Tags           []string     `json:"tags,omitempty"`
	Priority       string       `json:"priority,omitempty"`
	ScheduledAt    string       `json:"scheduledAt,omitempty"`
	Metadata       interface{}  `json:"metadata,omitempty"`
	IdempotencyKey string       `json:"-"`
}

// SendEmailResponse is returned by Emails.Send.
type SendEmailResponse struct {
	Message struct {
		ID          string `json:"id"`
		MessageID   string `json:"messageId"`
		Status      string `json:"status"`
		Recipients  int    `json:"recipients"`
		ScheduledAt string `json:"scheduledAt,omitempty"`
		CreatedAt   string `json:"createdAt"`
	} `json:"message"`
}

// Send sends a single transactional email.
func (a *EmailsAPI) Send(ctx context.Context, req *SendEmailRequest) (*SendEmailResponse, error) {
	var resp SendEmailResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/messages", req, &resp, req.IdempotencyKey)
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
	err := a.client.do(ctx, http.MethodGet, "/v1/messages/"+id, nil, &resp)
	return &resp, err
}

// ListEmailsOptions filters for the List endpoint.
type ListEmailsOptions struct {
	Status string
	Limit  int
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
	query := fmt.Sprintf("?limit=%d&offset=%d", optInt(o.Limit, 20), o.Offset)
	if o.Status != "" {
		query += "&status=" + o.Status
	}
	if o.Tag != "" {
		query += "&tag=" + o.Tag
	}
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

// Create adds a new domain and returns the DNS records to configure.
func (a *DomainsAPI) Create(ctx context.Context, req *CreateDomainRequest) (*CreateDomainResponse, error) {
	var resp CreateDomainResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/domains", req, &resp)
	return &resp, err
}

// Get retrieves a domain by its ID.
func (a *DomainsAPI) Get(ctx context.Context, id string) (*struct {
	Domain Domain `json:"domain"`
}, error) {
	var resp struct {
		Domain Domain `json:"domain"`
	}
	err := a.client.do(ctx, http.MethodGet, "/v1/domains/"+id, nil, &resp)
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
	err := a.client.do(ctx, http.MethodPost, "/v1/domains/"+id+"/verify", nil, &resp)
	return &resp, err
}

// Delete removes a domain.
func (a *DomainsAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/domains/"+id, nil, nil)
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
	err := a.client.do(ctx, http.MethodGet, "/v1/domains/"+id+"/health", nil, &resp)
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

// Create registers a new webhook endpoint.
func (a *WebhooksAPI) Create(ctx context.Context, req *CreateWebhookRequest) (*struct {
	Webhook Webhook `json:"webhook"`
}, error) {
	var resp struct {
		Webhook Webhook `json:"webhook"`
	}
	err := a.client.do(ctx, http.MethodPost, "/v1/webhooks", req, &resp)
	return &resp, err
}

// List retrieves all webhooks for the tenant.
func (a *WebhooksAPI) List(ctx context.Context) (*struct {
	Webhooks []Webhook `json:"webhooks"`
}, error) {
	var resp struct {
		Webhooks []Webhook `json:"webhooks"`
	}
	err := a.client.do(ctx, http.MethodGet, "/v1/webhooks", nil, &resp)
	return &resp, err
}

// Get retrieves a webhook by its ID.
func (a *WebhooksAPI) Get(ctx context.Context, id string) (*struct {
	Webhook Webhook `json:"webhook"`
}, error) {
	var resp struct {
		Webhook Webhook `json:"webhook"`
	}
	err := a.client.do(ctx, http.MethodGet, "/v1/webhooks/"+id, nil, &resp)
	return &resp, err
}

// UpdateWebhookRequest is the request body for updating a webhook.
type UpdateWebhookRequest struct {
	URL    string   `json:"url,omitempty"`
	Events []string `json:"events,omitempty"`
	Secret string   `json:"secret,omitempty"`
	Active *bool    `json:"active,omitempty"`
}

// Update modifies a webhook's URL, event subscriptions, or active status.
func (a *WebhooksAPI) Update(ctx context.Context, id string, req *UpdateWebhookRequest) (*struct {
	Webhook Webhook `json:"webhook"`
}, error) {
	var resp struct {
		Webhook Webhook `json:"webhook"`
	}
	err := a.client.do(ctx, http.MethodPatch, "/v1/webhooks/"+id, req, &resp)
	return &resp, err
}

// Delete removes a webhook.
func (a *WebhooksAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/webhooks/"+id, nil, nil)
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

// Create registers a new email template.
func (a *TemplatesAPI) Create(ctx context.Context, req *CreateTemplateRequest) (*struct {
	Template Template `json:"template"`
}, error) {
	var resp struct {
		Template Template `json:"template"`
	}
	err := a.client.do(ctx, http.MethodPost, "/v1/templates", req, &resp)
	return &resp, err
}

// Get retrieves a template by its ID.
func (a *TemplatesAPI) Get(ctx context.Context, id string) (*struct {
	Template Template `json:"template"`
}, error) {
	var resp struct {
		Template Template `json:"template"`
	}
	err := a.client.do(ctx, http.MethodGet, "/v1/templates/"+id, nil, &resp)
	return &resp, err
}

// GetBySlug retrieves a template by its unique slug.
func (a *TemplatesAPI) GetBySlug(ctx context.Context, slug string) (*struct {
	Template Template `json:"template"`
}, error) {
	var resp struct {
		Template Template `json:"template"`
	}
	err := a.client.do(ctx, http.MethodGet, "/v1/templates/slug/"+slug, nil, &resp)
	return &resp, err
}

// ListTemplatesOptions filters for the Templates.List endpoint.
type ListTemplatesOptions struct {
	Limit  int
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
	query := fmt.Sprintf("?limit=%d&offset=%d", optInt(o.Limit, 20), o.Offset)
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

// Update modifies a template. A new version is created automatically.
func (a *TemplatesAPI) Update(ctx context.Context, id string, req *UpdateTemplateRequest) (*struct {
	Template Template `json:"template"`
}, error) {
	var resp struct {
		Template Template `json:"template"`
	}
	err := a.client.do(ctx, http.MethodPatch, "/v1/templates/"+id, req, &resp)
	return &resp, err
}

// Delete removes a template and all its versions.
func (a *TemplatesAPI) Delete(ctx context.Context, id string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/templates/"+id, nil, nil)
}

// RenderTemplateRequest is the request body for rendering a template.
type RenderTemplateRequest struct {
	Data map[string]interface{} `json:"data"`
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
	err := a.client.do(ctx, http.MethodPost, "/v1/templates/"+id+"/render", &RenderTemplateRequest{Data: data}, &resp)
	return &resp, err
}

// ValidateReactEmailResponse is returned by Templates.ValidateReactEmail.
type ValidateReactEmailResponse struct {
	Valid  bool     `json:"valid"`
	Errors []string `json:"errors,omitempty"`
}

// ValidateReactEmail validates a React Email JSX source string without saving it.
func (a *TemplatesAPI) ValidateReactEmail(ctx context.Context, source string) (*ValidateReactEmailResponse, error) {
	var resp ValidateReactEmailResponse
	err := a.client.do(ctx, http.MethodPost, "/v1/templates/react-email/validate",
		map[string]string{"source": source}, &resp)
	return &resp, err
}

// ReactEmailStarterResponse is returned by Templates.ReactEmailStarter.
type ReactEmailStarterResponse struct {
	Source string `json:"source"`
	Name   string `json:"name"`
}

// ReactEmailStarter retrieves a React Email JSX starter template.
func (a *TemplatesAPI) ReactEmailStarter(ctx context.Context, componentName string) (*ReactEmailStarterResponse, error) {
	var resp ReactEmailStarterResponse
	err := a.client.do(ctx, http.MethodGet,
		"/v1/templates/react-email/starter?name="+componentName, nil, &resp)
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
	Limit  int
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
	query := fmt.Sprintf("?limit=%d&offset=%d", optInt(o.Limit, 50), o.Offset)
	if o.Reason != "" {
		query += "&reason=" + o.Reason
	}
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
	err := a.client.do(ctx, http.MethodGet, "/v1/suppressions/check?email="+email, nil, &resp)
	return &resp, err
}

// Delete removes an email from the suppression list.
func (a *SuppressionsAPI) Delete(ctx context.Context, email string) error {
	return a.client.do(ctx, http.MethodDelete, "/v1/suppressions/"+email, nil, nil)
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
	Limit     int
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
	query := fmt.Sprintf("?limit=%d&offset=%d", optInt(o.Limit, 50), o.Offset)
	if o.Type != "" {
		query += "&type=" + o.Type
	}
	if o.MessageID != "" {
		query += "&messageId=" + o.MessageID
	}
	if o.DomainID != "" {
		query += "&domainId=" + o.DomainID
	}
	if o.Start != "" {
		query += "&start=" + o.Start
	}
	if o.End != "" {
		query += "&end=" + o.End
	}
	var resp ListEventsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/events"+query, nil, &resp)
	return &resp, err
}

// GetByMessage retrieves all events for a specific sent message.
func (a *EventsAPI) GetByMessage(ctx context.Context, messageID string) (*ListEventsResponse, error) {
	var resp ListEventsResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/events?messageId="+messageID+"&limit=100", nil, &resp)
	return &resp, err
}

// GetEventResponse wraps a single event resource.
type GetEventResponse struct {
	Event Event `json:"event"`
}

// Get retrieves a single event by its ID.
func (a *EventsAPI) Get(ctx context.Context, eventID string) (*GetEventResponse, error) {
	var resp GetEventResponse
	err := a.client.do(ctx, http.MethodGet, "/v1/events/"+eventID, nil, &resp)
	return &resp, err
}

func optInt(v, def int) int {
	if v == 0 {
		return def
	}
	return v
}
