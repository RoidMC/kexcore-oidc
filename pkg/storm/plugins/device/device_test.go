// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package device

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

// mockDeviceAuthStore implements storm.DeviceAuthStore for testing.
type mockDeviceAuthStore struct {
	entries map[string]*storm.DeviceAuthorizationState
	byCode  map[string]*storm.DeviceAuthorizationState
}

func newMockDeviceAuthStore() *mockDeviceAuthStore {
	return &mockDeviceAuthStore{
		entries: make(map[string]*storm.DeviceAuthorizationState),
		byCode:  make(map[string]*storm.DeviceAuthorizationState),
	}
}

func (m *mockDeviceAuthStore) StoreDeviceAuthorization(_ context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	state := &storm.DeviceAuthorizationState{
		DeviceCode: deviceCode,
		ClientID:   clientID,
		UserCode:   userCode,
		Expires:    expires,
		Scopes:     scopes,
	}
	m.entries[deviceCode] = state
	m.byCode[userCode] = state
	return nil
}

func (m *mockDeviceAuthStore) GetDeviceAuthorizationState(_ context.Context, _, deviceCode string) (*storm.DeviceAuthorizationState, error) {
	state, ok := m.entries[deviceCode]
	if !ok {
		return nil, fmt.Errorf("device authorization not found")
	}
	return state, nil
}

func (m *mockDeviceAuthStore) GetDeviceAuthorizationByUserCode(_ context.Context, userCode string) (*storm.DeviceAuthorizationState, error) {
	state, ok := m.byCode[userCode]
	if !ok {
		return nil, fmt.Errorf("device authorization not found")
	}
	return state, nil
}

func (m *mockDeviceAuthStore) ApproveDeviceAuthorization(_ context.Context, userCode, subject string) error {
	state, ok := m.byCode[userCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	state.Done = true
	state.Subject = subject
	return nil
}

func (m *mockDeviceAuthStore) DenyDeviceAuthorization(_ context.Context, userCode string) error {
	state, ok := m.byCode[userCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	state.Denied = true
	return nil
}

func (m *mockDeviceAuthStore) UpdateDeviceAuthorizationPoll(_ context.Context, _, deviceCode string, lastPoll time.Time) error {
	state, ok := m.entries[deviceCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	state.LastPoll = lastPoll
	return nil
}

func (m *mockDeviceAuthStore) UpdateDeviceAuthorizationInterval(_ context.Context, _, deviceCode string, increment int) error {
	state, ok := m.entries[deviceCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	state.Interval += increment
	return nil
}

// mockClientStore implements storm.ClientStore for testing.
type mockClientStore struct {
	clients map[string]storm.Client
}

func newMockClientStore() *mockClientStore {
	return &mockClientStore{
		clients: make(map[string]storm.Client),
	}
}

func (m *mockClientStore) GetClientByClientID(_ context.Context, clientID string) (storm.Client, error) {
	client, ok := m.clients[clientID]
	if !ok {
		return nil, fmt.Errorf("client not found: %s", clientID)
	}
	return client, nil
}

func (m *mockClientStore) AuthorizeClientIDSecret(_ context.Context, clientID, _ string) error {
	_, ok := m.clients[clientID]
	if !ok {
		return fmt.Errorf("client not found: %s", clientID)
	}
	return nil
}

func (m *mockClientStore) GetClientByClientIDAndSecret(_ context.Context, clientID, _ string) (storm.Client, error) {
	return m.GetClientByClientID(context.Background(), clientID)
}

// mockClient implements storm.Client for testing.
type mockClient struct {
	id         string
	authMethod protocol.AuthMethod
	grantTypes []protocol.GrantType
}

func (c *mockClient) GetID() string                   { return c.id }
func (c *mockClient) AuthMethod() protocol.AuthMethod { return c.authMethod }
func (c *mockClient) LoginURL(_ string) string        { return "http://localhost/login" }

// grantTypesProvider extends mockClient to provide grant types.
type mockClientWithGrantTypes struct {
	mockClient
}

func (c *mockClientWithGrantTypes) GrantTypes() []protocol.GrantType { return c.grantTypes }

func TestHandleDeviceAuthorization(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	// Add a test client
	clientStore.clients["test-client"] = &mockClientWithGrantTypes{
		mockClient: mockClient{
			id:         "test-client",
			authMethod: protocol.AuthMethodNone,
			grantTypes: []protocol.GrantType{protocol.GrantTypeDeviceCode},
		},
	}

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	// Test device authorization request
	body := "client_id=test-client&scope=openid profile"
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleDeviceAuthorization(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp protocol.DeviceAuthorizationResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal response: %v", err)
	}

	if resp.DeviceCode == "" {
		t.Error("expected device_code to be non-empty")
	}
	if resp.UserCode == "" {
		t.Error("expected user_code to be non-empty")
	}
	if resp.VerificationURI == "" {
		t.Error("expected verification_uri to be non-empty")
	}
	if resp.VerificationURIComplete == "" {
		t.Error("expected verification_uri_complete to be non-empty")
	}
	if resp.ExpiresIn != 900 {
		t.Errorf("expected expires_in to be 900, got %d", resp.ExpiresIn)
	}
	if resp.Interval != 5 {
		t.Errorf("expected interval to be 5, got %d", resp.Interval)
	}
}

func TestHandleDeviceAuthorization_MissingClientID(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	body := "scope=openid"
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleDeviceAuthorization(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var errResp protocol.Error
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to unmarshal error response: %v", err)
	}

	if errResp.ErrorType != protocol.InvalidRequest {
		t.Errorf("expected error type 'invalid_request', got '%s'", errResp.ErrorType)
	}
}

func TestHandleDeviceAuthorization_ClientNotFound(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	body := "client_id=nonexistent-client&scope=openid"
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleDeviceAuthorization(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401, got %d: %s", w.Code, w.Body.String())
	}

	var errResp protocol.Error
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to unmarshal error response: %v", err)
	}

	if errResp.ErrorType != protocol.InvalidClient {
		t.Errorf("expected error type 'invalid_client', got '%s'", errResp.ErrorType)
	}
}

func TestHandleDeviceAuthorization_MissingGrantType(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	// Add a client without device_code grant type
	clientStore.clients["test-client"] = &mockClientWithGrantTypes{
		mockClient: mockClient{
			id:         "test-client",
			authMethod: protocol.AuthMethodNone,
			grantTypes: []protocol.GrantType{protocol.GrantTypeCode},
		},
	}

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	body := "client_id=test-client&scope=openid"
	req := httptest.NewRequest(http.MethodPost, "/device_authorization", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()

	p.handleDeviceAuthorization(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
	}

	var errResp protocol.Error
	if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
		t.Fatalf("failed to unmarshal error response: %v", err)
	}

	if errResp.ErrorType != protocol.UnauthorizedClient {
		t.Errorf("expected error type 'unauthorized_client', got '%s'", errResp.ErrorType)
	}
}

func TestGenerateRandomUserCode(t *testing.T) {
	code := generateRandomUserCode(8)

	if len(code) != 9 { // 8 chars + 1 hyphen
		t.Errorf("expected code length 9, got %d", len(code))
	}

	// Check hyphen is in the middle
	if code[4] != '-' {
		t.Errorf("expected hyphen at position 4, got '%c'", code[4])
	}

	// Check all characters are valid
	validChars := "BCDFGHJKLMNPQRSTVWXYZ"
	for i, c := range code {
		if i == 4 {
			continue // skip hyphen
		}
		if !strings.ContainsRune(validChars, c) {
			t.Errorf("invalid character '%c' at position %d", c, i)
		}
	}
}

func TestGenerateRandomCode(t *testing.T) {
	code1 := generateRandomCode(32)
	code2 := generateRandomCode(32)

	if code1 == code2 {
		t.Error("expected two random codes to be different")
	}

	if len(code1) == 0 {
		t.Error("expected code to be non-empty")
	}
}

// --- Device verification page tests (RFC 8628 §3.3) ---

func TestHandleDevicePage(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	// Store a device authorization
	if err := deviceStore.StoreDeviceAuthorization(context.Background(), "test-client", "device-123", "ABCD-EFGH", time.Now().Add(15*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("failed to store device auth: %v", err)
	}

	// Test GET /device with user_code
	req := httptest.NewRequest(http.MethodGet, "/device?user_code=ABCD-EFGH", nil)
	w := httptest.NewRecorder()
	p.handleDevicePage(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "ABCD-EFGH") {
		t.Error("expected response to contain user_code")
	}
}

func TestHandleDevicePage_Expired(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	// Store an expired device authorization
	if err := deviceStore.StoreDeviceAuthorization(context.Background(), "test-client", "device-123", "ABCD-EFGH", time.Now().Add(-1*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("failed to store device auth: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/device?user_code=ABCD-EFGH", nil)
	w := httptest.NewRecorder()
	p.handleDevicePage(w, req)

	// Verification page renders as 200 even for expired codes
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	body := w.Body.String()
	if !strings.Contains(body, "expired") {
		t.Error("expected response to contain 'expired'")
	}
}

func TestHandleDeviceApproval(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	// Store a device authorization
	if err := deviceStore.StoreDeviceAuthorization(context.Background(), "test-client", "device-123", "ABCD-EFGH", time.Now().Add(15*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("failed to store device auth: %v", err)
	}

	// Test POST /device approve
	body := "user_code=ABCD-EFGH&action=approve&subject=user-123"
	req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.handleDeviceApproval(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Verify the state is approved
	state, err := deviceStore.GetDeviceAuthorizationByUserCode(context.Background(), "ABCD-EFGH")
	if err != nil {
		t.Fatalf("failed to get device auth: %v", err)
	}
	if !state.Done {
		t.Error("expected device authorization to be approved")
	}
	if state.Subject != "user-123" {
		t.Errorf("expected subject 'user-123', got '%s'", state.Subject)
	}
}

func TestHandleDeviceApproval_Deny(t *testing.T) {
	deviceStore := newMockDeviceAuthStore()
	clientStore := newMockClientStore()

	p := NewWithConfig(Config{
		Store:       deviceStore,
		ClientStore: clientStore,
		Lifetime:    15 * time.Minute,
		Interval:    5 * time.Second,
	})

	// Store a device authorization
	if err := deviceStore.StoreDeviceAuthorization(context.Background(), "test-client", "device-123", "ABCD-EFGH", time.Now().Add(15*time.Minute), []string{"openid"}); err != nil {
		t.Fatalf("failed to store device auth: %v", err)
	}

	// Test POST /device deny
	body := "user_code=ABCD-EFGH&action=deny"
	req := httptest.NewRequest(http.MethodPost, "/device", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	p.handleDeviceApproval(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", w.Code)
	}

	// Verify the state is denied
	state, err := deviceStore.GetDeviceAuthorizationByUserCode(context.Background(), "ABCD-EFGH")
	if err != nil {
		t.Fatalf("failed to get device auth: %v", err)
	}
	if !state.Denied {
		t.Error("expected device authorization to be denied")
	}
}
