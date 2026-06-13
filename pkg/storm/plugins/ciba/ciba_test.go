package ciba

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// --- mock stores ---

type mockCIBAStore struct {
	requests map[string]*storm.CIBARequest
}

func newMockCIBAStore() *mockCIBAStore {
	return &mockCIBAStore{requests: make(map[string]*storm.CIBARequest)}
}

func (m *mockCIBAStore) StoreCIBARequest(_ context.Context, req *storm.CIBARequest) error {
	m.requests[req.AuthReqID] = req
	return nil
}

func (m *mockCIBAStore) GetCIBARequestByAuthReqID(_ context.Context, authReqID string) (*storm.CIBARequest, error) {
	req, ok := m.requests[authReqID]
	if !ok {
		return nil, fmt.Errorf("ciba request not found")
	}
	return req, nil
}

func (m *mockCIBAStore) UpdateCIBARequestStatus(_ context.Context, authReqID string, status protocol.CIBAStatus, approvedScopes []string) error {
	req, ok := m.requests[authReqID]
	if !ok {
		return fmt.Errorf("ciba request not found")
	}
	req.Status = status
	req.ApprovedScopes = approvedScopes
	return nil
}

func (m *mockCIBAStore) GetPendingCIBARequests(_ context.Context, subject string) ([]*storm.CIBARequest, error) {
	var result []*storm.CIBARequest
	for _, req := range m.requests {
		if req.Subject == subject && req.Status == protocol.CIBAStatusPending {
			result = append(result, req)
		}
	}
	return result, nil
}

func (m *mockCIBAStore) UpdateCIBAPoll(_ context.Context, authReqID string, lastPoll time.Time) error {
	req, ok := m.requests[authReqID]
	if !ok {
		return fmt.Errorf("ciba request not found")
	}
	req.LastPoll = lastPoll
	return nil
}

func (m *mockCIBAStore) UpdateCIBAInterval(_ context.Context, authReqID string, increment int) error {
	req, ok := m.requests[authReqID]
	if !ok {
		return fmt.Errorf("ciba request not found")
	}
	req.Interval += increment
	return nil
}

type mockClientStore struct {
	clients map[string]*mockClient
}

type mockClient struct {
	id         string
	secret     string
	grantTypes []protocol.GrantType
}

func (c *mockClient) GetID() string                   { return c.id }
func (c *mockClient) AuthMethod() protocol.AuthMethod { return protocol.AuthMethodBasic }
func (c *mockClient) LoginURL(_ string) string        { return "" }

// GrantTypes implements the optional grantTypesProvider interface.
func (c *mockClient) GrantTypes() []protocol.GrantType { return c.grantTypes }

func newMockClientStore() *mockClientStore {
	return &mockClientStore{clients: make(map[string]*mockClient)}
}

func (m *mockClientStore) GetClientByClientID(_ context.Context, clientID string) (storm.Client, error) {
	c, ok := m.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found")
	}
	return c, nil
}

func (m *mockClientStore) AuthorizeClientIDSecret(_ context.Context, clientID, clientSecret string) error {
	c, ok := m.clients[clientID]
	if !ok {
		return protocol.ErrInvalidClient()
	}
	if c.secret != clientSecret {
		return protocol.ErrInvalidClient().WithDescription("invalid client secret")
	}
	return nil
}

// mockNotifier implements storm.CIBANotificationCallback for testing.
type mockNotifier struct {
	called    bool
	lastReq   *storm.CIBARequest
	returnErr error
}

func (n *mockNotifier) OnCIBAStatusChange(_ context.Context, req *storm.CIBARequest) error {
	n.called = true
	n.lastReq = req
	return n.returnErr
}

// --- helpers ---

func setupPlugin(cibaStore *mockCIBAStore, clientStore *mockClientStore, notifier *mockNotifier) *Plugin {
	p := &Plugin{
		store:       cibaStore,
		clientStore: clientStore,
		lifetime:    5 * time.Minute,
		interval:    5 * time.Second,
		cibaTmpl:    cibaTmpl,
	}
	if notifier != nil {
		p.notifier = notifier
	}
	return p
}

func newCIBAPlugin(cs *mockCIBAStore, cls *mockClientStore) *Plugin {
	return setupPlugin(cs, cls, nil)
}

// --- tests ---

// CIBA Core 1.0 §7.1.1: POST /bc-authorize creates a pending request
func TestBackchannelAuth_Success(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	cls.clients["test-client"] = &mockClient{
		id:         "test-client",
		secret:     "secret",
		grantTypes: []protocol.GrantType{protocol.GrantTypeCIBA},
	}

	p := newCIBAPlugin(cs, cls)

	form := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"secret"},
		"login_hint":    {"user@example.com"},
		"scope":         {"openid profile"},
	}

	req := httptest.NewRequest(http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleBackchannelAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp protocol.BackchannelAuthResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.AuthReqID == "" {
		t.Fatal("expected auth_req_id")
	}
	if resp.ExpiresIn != 300 {
		t.Errorf("expected expires_in=300, got %d", resp.ExpiresIn)
	}
	if resp.Interval != 5 {
		t.Errorf("expected interval=5, got %d", resp.Interval)
	}

	// Verify stored
	stored, err := cs.GetCIBARequestByAuthReqID(context.Background(), resp.AuthReqID)
	if err != nil {
		t.Fatalf("failed to get stored request: %v", err)
	}
	if stored.ClientID != "test-client" {
		t.Errorf("expected client_id=test-client, got %s", stored.ClientID)
	}
	if stored.Subject != "user@example.com" {
		t.Errorf("expected subject=user@example.com, got %s", stored.Subject)
	}
	if stored.Status != protocol.CIBAStatusPending {
		t.Errorf("expected status=pending, got %s", stored.Status)
	}
	if stored.DeliveryMode != protocol.CIBAModePoll {
		t.Errorf("expected delivery_mode=poll, got %s", stored.DeliveryMode)
	}
}

// CIBA Core 1.0 §7.1.1: client_notification_token triggers ping mode
func TestBackchannelAuth_PingMode(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	cls.clients["test-client"] = &mockClient{
		id:         "test-client",
		secret:     "secret",
		grantTypes: []protocol.GrantType{protocol.GrantTypeCIBA},
	}

	p := newCIBAPlugin(cs, cls)

	form := url.Values{
		"client_id":                 {"test-client"},
		"client_secret":             {"secret"},
		"login_hint":                {"user@example.com"},
		"scope":                     {"openid"},
		"client_notification_token": {"notif-token-123"},
	}

	req := httptest.NewRequest(http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleBackchannelAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp protocol.BackchannelAuthResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	stored, _ := cs.GetCIBARequestByAuthReqID(context.Background(), resp.AuthReqID)
	if stored.DeliveryMode != protocol.CIBAModePing {
		t.Errorf("expected delivery_mode=ping, got %s", stored.DeliveryMode)
	}
	if stored.ClientNotificationToken != "notif-token-123" {
		t.Errorf("expected client_notification_token=notif-token-123, got %s", stored.ClientNotificationToken)
	}
}

// CIBA Core 1.0 §7.1.1: missing hints returns invalid_request
func TestBackchannelAuth_MissingHints(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	cls.clients["test-client"] = &mockClient{
		id:         "test-client",
		secret:     "secret",
		grantTypes: []protocol.GrantType{protocol.GrantTypeCIBA},
	}

	p := newCIBAPlugin(cs, cls)

	form := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"secret"},
		"scope":         {"openid"},
	}

	req := httptest.NewRequest(http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleBackchannelAuth(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// CIBA Core 1.0 §7.1.1: client without ciba grant type is rejected
func TestBackchannelAuth_ClientMissingGrantType(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	cls.clients["test-client"] = &mockClient{
		id:         "test-client",
		secret:     "secret",
		grantTypes: []protocol.GrantType{protocol.GrantTypeCode},
	}

	p := newCIBAPlugin(cs, cls)

	form := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"secret"},
		"login_hint":    {"user@example.com"},
	}

	req := httptest.NewRequest(http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleBackchannelAuth(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// CIBA Core 1.0 §7.1.1: invalid client credentials rejected
func TestBackchannelAuth_InvalidCredentials(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	cls.clients["test-client"] = &mockClient{
		id:         "test-client",
		secret:     "secret",
		grantTypes: []protocol.GrantType{protocol.GrantTypeCIBA},
	}

	p := newCIBAPlugin(cs, cls)

	form := url.Values{
		"client_id":     {"test-client"},
		"client_secret": {"wrong-secret"},
		"login_hint":    {"user@example.com"},
	}

	req := httptest.NewRequest(http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleBackchannelAuth(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// Approval page: GET /ciba with valid auth_req_id
func TestApprovalPage_ValidRequest(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	cs.requests["test-req-1"] = &storm.CIBARequest{
		AuthReqID:      "test-req-1",
		ClientID:       "test-client",
		Scope:          "openid profile",
		Subject:        "user@example.com",
		BindingMessage: "Login from mobile app",
		Status:         protocol.CIBAStatusPending,
		ExpiresAt:      time.Now().Add(5 * time.Minute),
	}

	req := httptest.NewRequest(http.MethodGet, "/ciba?auth_req_id=test-req-1", nil)
	w := httptest.NewRecorder()

	p.handleApprovalPage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "test-client") {
		t.Error("expected client ID in response")
	}
	if !strings.Contains(body, "Login from mobile app") {
		t.Error("expected binding message in response")
	}
}

// Approval page: expired request shows error
func TestApprovalPage_ExpiredRequest(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	cs.requests["expired-req"] = &storm.CIBARequest{
		AuthReqID: "expired-req",
		ClientID:  "test-client",
		Status:    protocol.CIBAStatusPending,
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	req := httptest.NewRequest(http.MethodGet, "/ciba?auth_req_id=expired-req", nil)
	w := httptest.NewRecorder()

	p.handleApprovalPage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "expired") {
		t.Error("expected expired message in response")
	}
}

// Approval page: unknown auth_req_id shows error
func TestApprovalPage_UnknownRequest(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	req := httptest.NewRequest(http.MethodGet, "/ciba?auth_req_id=unknown", nil)
	w := httptest.NewRecorder()

	p.handleApprovalPage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "Invalid or unknown") {
		t.Error("expected invalid request message in response")
	}
}

// Approval action: approve
func TestApprovalAction_Approve(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	cs.requests["test-req-1"] = &storm.CIBARequest{
		AuthReqID:       "test-req-1",
		ClientID:        "test-client",
		Scope:           "openid",
		Subject:         "user@example.com",
		RequestedScopes: []string{"openid"},
		Status:          protocol.CIBAStatusPending,
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		DeliveryMode:    protocol.CIBAModePoll,
	}

	form := url.Values{
		"auth_req_id": {"test-req-1"},
		"action":      {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	stored, _ := cs.GetCIBARequestByAuthReqID(context.Background(), "test-req-1")
	if stored.Status != protocol.CIBAStatusApproved {
		t.Errorf("expected status=approved, got %s", stored.Status)
	}
}

// Approval action: deny
func TestApprovalAction_Deny(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	cs.requests["test-req-1"] = &storm.CIBARequest{
		AuthReqID:    "test-req-1",
		ClientID:     "test-client",
		Status:       protocol.CIBAStatusPending,
		ExpiresAt:    time.Now().Add(5 * time.Minute),
		DeliveryMode: protocol.CIBAModePoll,
	}

	form := url.Values{
		"auth_req_id": {"test-req-1"},
		"action":      {"deny"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	stored, _ := cs.GetCIBARequestByAuthReqID(context.Background(), "test-req-1")
	if stored.Status != protocol.CIBAStatusDenied {
		t.Errorf("expected status=denied, got %s", stored.Status)
	}
}

// Approval action: expired request rejected
func TestApprovalAction_ExpiredRequest(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	cs.requests["expired-req"] = &storm.CIBARequest{
		AuthReqID: "expired-req",
		ClientID:  "test-client",
		Status:    protocol.CIBAStatusPending,
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}

	form := url.Values{
		"auth_req_id": {"expired-req"},
		"action":      {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// Approval action: already processed request rejected
func TestApprovalAction_AlreadyProcessed(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	cs.requests["done-req"] = &storm.CIBARequest{
		AuthReqID: "done-req",
		ClientID:  "test-client",
		Status:    protocol.CIBAStatusApproved,
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	form := url.Values{
		"auth_req_id": {"done-req"},
		"action":      {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", w.Code)
	}
}

// CIBA Core 1.0 §10: ping delivery mode triggers notification callback
func TestApprovalAction_PingNotification(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	notifier := &mockNotifier{}
	p := setupPlugin(cs, cls, notifier)

	cs.requests["ping-req"] = &storm.CIBARequest{
		AuthReqID:               "ping-req",
		ClientID:                "test-client",
		Scope:                   "openid",
		Subject:                 "user@example.com",
		RequestedScopes:         []string{"openid"},
		Status:                  protocol.CIBAStatusPending,
		ExpiresAt:               time.Now().Add(5 * time.Minute),
		DeliveryMode:            protocol.CIBAModePing,
		ClientNotificationToken: "notif-token",
	}

	form := url.Values{
		"auth_req_id": {"ping-req"},
		"action":      {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	if !notifier.called {
		t.Error("expected notification callback to be called for ping mode")
	}
	if notifier.lastReq == nil || notifier.lastReq.AuthReqID != "ping-req" {
		t.Error("expected notification callback to receive the correct request")
	}
}

// Poll delivery mode does NOT trigger notification callback
func TestApprovalAction_PollNoNotification(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	notifier := &mockNotifier{}
	p := setupPlugin(cs, cls, notifier)

	cs.requests["poll-req"] = &storm.CIBARequest{
		AuthReqID:       "poll-req",
		ClientID:        "test-client",
		RequestedScopes: []string{"openid"},
		Status:          protocol.CIBAStatusPending,
		ExpiresAt:       time.Now().Add(5 * time.Minute),
		DeliveryMode:    protocol.CIBAModePoll,
	}

	form := url.Values{
		"auth_req_id": {"poll-req"},
		"action":      {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	if notifier.called {
		t.Error("expected notification callback NOT to be called for poll mode")
	}
}

// Notification callback error does not affect the approval response
func TestApprovalAction_PingNotificationError(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	notifier := &mockNotifier{returnErr: fmt.Errorf("network error")}
	p := setupPlugin(cs, cls, notifier)

	cs.requests["ping-err"] = &storm.CIBARequest{
		AuthReqID:               "ping-err",
		ClientID:                "test-client",
		RequestedScopes:         []string{"openid"},
		Status:                  protocol.CIBAStatusPending,
		ExpiresAt:               time.Now().Add(5 * time.Minute),
		DeliveryMode:            protocol.CIBAModePing,
		ClientNotificationToken: "notif-token",
	}

	form := url.Values{
		"auth_req_id": {"ping-err"},
		"action":      {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	// Should still succeed even if notification fails
	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}

	stored, _ := cs.GetCIBARequestByAuthReqID(context.Background(), "ping-err")
	if stored.Status != protocol.CIBAStatusApproved {
		t.Errorf("expected status=approved even with notification error, got %s", stored.Status)
	}
}

// No notifier does not panic
func TestApprovalAction_NoNotifier(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	p := newCIBAPlugin(cs, cls)

	cs.requests["no-notif"] = &storm.CIBARequest{
		AuthReqID:               "no-notif",
		ClientID:                "test-client",
		RequestedScopes:         []string{"openid"},
		Status:                  protocol.CIBAStatusPending,
		ExpiresAt:               time.Now().Add(5 * time.Minute),
		DeliveryMode:            protocol.CIBAModePing,
		ClientNotificationToken: "notif-token",
	}

	form := url.Values{
		"auth_req_id": {"no-notif"},
		"action":      {"approve"},
	}

	req := httptest.NewRequest(http.MethodPost, "/ciba", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleApprovalAction(w, req)

	if w.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", w.Code)
	}
}

// CIBA Core 1.0 §7.1.1: requested_expiry overrides default lifetime
func TestBackchannelAuth_RequestedExpiry(t *testing.T) {
	cs := newMockCIBAStore()
	cls := newMockClientStore()
	cls.clients["test-client"] = &mockClient{
		id:         "test-client",
		secret:     "secret",
		grantTypes: []protocol.GrantType{protocol.GrantTypeCIBA},
	}

	p := newCIBAPlugin(cs, cls)

	form := url.Values{
		"client_id":        {"test-client"},
		"client_secret":    {"secret"},
		"login_hint":       {"user@example.com"},
		"scope":            {"openid"},
		"requested_expiry": {"60"}, // request 60 seconds (less than default 5m)
	}

	req := httptest.NewRequest(http.MethodPost, "/bc-authorize", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleBackchannelAuth(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp protocol.BackchannelAuthResponse
	json.Unmarshal(w.Body.Bytes(), &resp)

	if resp.ExpiresIn != 60 {
		t.Errorf("expected expires_in=60, got %d", resp.ExpiresIn)
	}

	stored, _ := cs.GetCIBARequestByAuthReqID(context.Background(), resp.AuthReqID)
	expectedExpiry := time.Now().Add(60 * time.Second)
	if stored.ExpiresAt.After(expectedExpiry.Add(2*time.Second)) || stored.ExpiresAt.Before(expectedExpiry.Add(-2*time.Second)) {
		t.Errorf("expected expiry around 60s from now, got %v", stored.ExpiresAt)
	}
}

// Plugin name is correct
func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	if p.Name() != "ciba" {
		t.Errorf("expected name=ciba, got %s", p.Name())
	}
}
