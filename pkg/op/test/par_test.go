// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package op_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/roidmc/kexcore-oidc/pkg/oidc"
	"github.com/roidmc/kexcore-oidc/pkg/op"
	"github.com/roidmc/kexcore-oidc/pkg/op/mock"
	"github.com/roidmc/kexcore-oidc/pkg/protocol"
)

type parTestServer struct {
	op.UnimplementedServer
	storage op.Storage
}

func (s *parTestServer) VerifyClient(ctx context.Context, r *op.Request[op.ClientCredentials]) (op.Client, error) {
	creds := r.Data
	clientID := creds.ClientID
	if clientID == "" {
		return nil, protocol.ErrInvalidClient().WithDescription("client_id is required")
	}

	client, err := s.storage.GetClientByClientID(ctx, clientID)
	if err != nil {
		return nil, protocol.ErrInvalidClient().WithDescription("client not found").WithParent(err)
	}

	if client.AuthMethod() != protocol.AuthMethodNone {
		if err := s.storage.AuthorizeClientIDSecret(ctx, clientID, creds.ClientSecret); err != nil {
			return nil, protocol.ErrInvalidClient().WithDescription("invalid client credentials").WithParent(err)
		}
	}
	return client, nil
}

func (s *parTestServer) PushedAuthorizationRequest(ctx context.Context, r *op.ClientRequest[oidc.AuthRequest]) (*op.Response, error) {
	authReq := r.Data
	client := r.Client

	if client.AuthMethod() == protocol.AuthMethodNone &&
		authReq.ResponseType == oidc.ResponseTypeCode &&
		authReq.CodeChallenge == "" {
		return nil, protocol.ErrInvalidRequest().WithDescription("public clients must use PKCE (code_challenge) for pushed authorization requests with response_type=code")
	}

	if authReq.RedirectURI == "" {
		return nil, protocol.ErrInvalidRequest().WithDescription("redirect_uri is required")
	}

	if err := op.ValidateAuthRequestParams(client, authReq); err != nil {
		return nil, err
	}

	parStorage, ok := s.storage.(op.PushedAuthRequestStorage)
	if !ok {
		return nil, protocol.ErrServerError().WithDescription("pushed authorization requests not supported")
	}

	requestURI, err := parStorage.StorePushedAuthRequest(ctx, client.GetID(), authReq, op.DefaultPushedAuthRequestLifetime)
	if err != nil {
		return nil, protocol.ErrServerError().WithDescription("unable to store pushed authorization request").WithParent(err)
	}

	return op.NewResponse(&oidc.PushedAuthResponse{
		RequestURI: requestURI,
		ExpiresIn:  int(op.DefaultPushedAuthRequestLifetime / time.Second),
	}), nil
}

type parStorageMock struct {
	op.Storage
	counter  atomic.Int64
	store    map[string]*parEntry
	forceErr error
}

type parEntry struct {
	authReq  *oidc.AuthRequest
	clientID string
}

func (s *parStorageMock) StorePushedAuthRequest(_ context.Context, clientID string, authReq *oidc.AuthRequest, _ time.Duration) (string, error) {
	if s.forceErr != nil {
		return "", s.forceErr
	}
	n := s.counter.Add(1)
	uri := fmt.Sprintf("urn:ietf:params:oauth:request_uri:test-%s-%d", clientID, n)
	s.store[uri] = &parEntry{authReq: authReq, clientID: clientID}
	return uri, nil
}

func (s *parStorageMock) PushedAuthRequestByURI(_ context.Context, clientID string, requestURI string) (*oidc.AuthRequest, error) {
	entry, ok := s.store[requestURI]
	if !ok {
		return nil, protocol.ErrInvalidRequest().WithDescription("invalid or expired request_uri")
	}
	if entry.clientID != clientID {
		return nil, protocol.ErrInvalidRequest().WithDescription("client_id mismatch")
	}
	return entry.authReq, nil
}

type parTestSetup struct {
	t       *testing.T
	handler http.Handler
	storage *parStorageMock
}

func newPARTestSetup(t *testing.T) *parTestSetup {
	ctrl := gomock.NewController(t)
	baseStorage := mock.NewMockStorage(ctrl)

	newMockClient := func(id string, appType op.ApplicationType, authMethod protocol.AuthMethod, uris []string, responseTypes []oidc.ResponseType) op.Client {
		c := mock.NewMockClient(ctrl)
		c.EXPECT().GetID().AnyTimes().Return(id)
		c.EXPECT().AuthMethod().AnyTimes().Return(authMethod)
		c.EXPECT().ApplicationType().AnyTimes().Return(appType)
		c.EXPECT().RedirectURIs().AnyTimes().Return(uris)
		c.EXPECT().ResponseTypes().AnyTimes().Return(responseTypes)
		c.EXPECT().LoginURL(gomock.Any()).AnyTimes().Return("login?id=test")
		c.EXPECT().IsScopeAllowed(gomock.Any()).AnyTimes().Return(false)
		c.EXPECT().DevMode().AnyTimes().Return(false)
		c.EXPECT().GrantTypes().AnyTimes().Return(nil)
		c.EXPECT().PostLogoutRedirectURIs().AnyTimes().Return(nil)
		c.EXPECT().IDTokenUserinfoClaimsAssertion().AnyTimes().Return(false)
		c.EXPECT().ClockSkew().AnyTimes().Return(time.Duration(0))
		c.EXPECT().RestrictAdditionalIdTokenScopes().AnyTimes().Return(func(scopes []string) []string { return scopes })
		c.EXPECT().RestrictAdditionalAccessTokenScopes().AnyTimes().Return(func(scopes []string) []string { return scopes })
		c.EXPECT().IDTokenLifetime().AnyTimes().Return(5 * time.Minute)
		c.EXPECT().AccessTokenType().AnyTimes().Return(op.AccessTokenTypeBearer)
		return c
	}

	webClient := newMockClient("web_client", op.ApplicationTypeWeb, protocol.AuthMethodBasic,
		[]string{"https://registered.com/callback", "http://registered.com/callback"},
		[]oidc.ResponseType{oidc.ResponseTypeCode})
	nativeClient := newMockClient("native_client", op.ApplicationTypeNative, protocol.AuthMethodNone,
		[]string{"custom://callback", "http://localhost:9999/callback"},
		[]oidc.ResponseType{oidc.ResponseTypeCode})

	baseStorage.EXPECT().GetClientByClientID(gomock.Any(), gomock.Any()).AnyTimes().DoAndReturn(
		func(_ context.Context, id string) (op.Client, error) {
			switch id {
			case "web_client":
				return webClient, nil
			case "native_client":
				return nativeClient, nil
			default:
				return nil, assert.AnError
			}
		})
	baseStorage.EXPECT().AuthorizeClientIDSecret(gomock.Any(), "web_client", "secret").AnyTimes().Return(nil)
	baseStorage.EXPECT().AuthorizeClientIDSecret(gomock.Any(), "web_client", gomock.Not("secret")).AnyTimes().Return(assert.AnError)
	baseStorage.EXPECT().AuthorizeClientIDSecret(gomock.Any(), gomock.Not("web_client"), gomock.Any()).AnyTimes().Return(assert.AnError)

	parStore := &parStorageMock{Storage: baseStorage, store: make(map[string]*parEntry)}

	server := &parTestServer{storage: parStore}
	handler := op.RegisterServer(server, op.Endpoints{
		Authorization:              op.NewEndpoint("authorize"),
		Token:                      op.NewEndpoint("token"),
		Introspection:              op.NewEndpoint("introspect"),
		Userinfo:                   op.NewEndpoint("userinfo"),
		Revocation:                 op.NewEndpoint("revoke"),
		EndSession:                 op.NewEndpoint("end-session"),
		JwksURI:                    op.NewEndpoint("keys"),
		PushedAuthorizationRequest: op.NewEndpoint("pushed_authorization_request"),
	})

	return &parTestSetup{t: t, handler: handler, storage: parStore}
}

func (s *parTestSetup) doRequest(form url.Values, basicAuth ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/pushed_authorization_request", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if len(basicAuth) == 2 {
		req.SetBasicAuth(basicAuth[0], basicAuth[1])
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec
}

func (s *parTestSetup) parsePARResponse(rec *httptest.ResponseRecorder) oidc.PushedAuthResponse {
	s.t.Helper()
	var resp oidc.PushedAuthResponse
	require.NoError(s.t, json.Unmarshal(rec.Body.Bytes(), &resp))
	return resp
}

func TestPushedAuthRequest_Success(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))

	resp := s.parsePARResponse(rec)
	assert.NotEmpty(t, resp.RequestURI)
	assert.Contains(t, resp.RequestURI, "urn:ietf:params:oauth:request_uri:")
	assert.Equal(t, 600, resp.ExpiresIn)
}

func TestPushedAuthRequest_PublicClientWithPKCE(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":             {"native_client"},
		"redirect_uri":          {"custom://callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method": {"S256"},
	}
	rec := s.doRequest(form)

	assert.Equal(t, http.StatusCreated, rec.Code)

	resp := s.parsePARResponse(rec)
	entry, ok := s.storage.store[resp.RequestURI]
	require.True(t, ok)
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", entry.authReq.CodeChallenge)
	assert.Equal(t, oidc.CodeChallengeMethodS256, entry.authReq.CodeChallengeMethod)
}

func TestPushedAuthRequest_PublicClientWithoutPKCE(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"native_client"},
		"redirect_uri":  {"custom://callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "public clients must use PKCE")
}

func TestPushedAuthRequest_MissingResponseType(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":    {"web_client"},
		"redirect_uri": {"https://registered.com/callback"},
		"scope":        {"openid"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "response type")
}

func TestPushedAuthRequest_MissingRedirectURI(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "redirect_uri")
}

func TestPushedAuthRequest_UnregisteredRedirectURI(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://attacker.example.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPushedAuthRequest_InvalidClientSecret(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "web_client", "wrong-secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_client")
}

func TestPushedAuthRequest_ClientSecretPost(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"client_secret": {"secret"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form)

	assert.Equal(t, http.StatusCreated, rec.Code)
}

func TestPushedAuthRequest_UnsupportedScopeStripped(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid admin:all"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusCreated, rec.Code)

	resp := s.parsePARResponse(rec)
	entry, ok := s.storage.store[resp.RequestURI]
	require.True(t, ok)
	assert.NotContains(t, entry.authReq.Scopes, "admin:all")
	assert.Contains(t, entry.authReq.Scopes, oidc.ScopeOpenID)
}

func TestPushedAuthRequest_CacheControlAndJSON(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusCreated, rec.Code)
	assert.Equal(t, "no-store", rec.Header().Get("Cache-Control"))
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/json")

	var resp oidc.PushedAuthResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.RequestURI)
	assert.Equal(t, 600, resp.ExpiresIn)
}

func TestPushedAuthRequest_StateAndNoncePreserved(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"test-state-123"},
		"nonce":         {"test-nonce-456"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	require.Equal(t, http.StatusCreated, rec.Code)

	resp := s.parsePARResponse(rec)
	entry, ok := s.storage.store[resp.RequestURI]
	require.True(t, ok)
	assert.Equal(t, "test-state-123", entry.authReq.State)
	assert.Equal(t, "test-nonce-456", entry.authReq.Nonce)
}

func TestPushedAuthRequest_PromptPreserved(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid profile"},
		"prompt":        {"consent"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	require.Equal(t, http.StatusCreated, rec.Code)

	resp := s.parsePARResponse(rec)
	entry, ok := s.storage.store[resp.RequestURI]
	require.True(t, ok)
	assert.Contains(t, entry.authReq.Prompt, "consent")
}

func TestPushedAuthRequest_WrongClientID(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"unknown_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "unknown_client", "secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPushedAuthRequest_MissingClientID(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form)

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "client_id")
}

func TestPushedAuthRequest_EmptyScope(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "scope")
}

func TestPushedAuthRequest_PromptNoneWithOthers(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"prompt":        {"none consent"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPushedAuthRequest_ResponseTypeMismatch(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"id_token"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestPushedAuthRequest_DuplicatePAR(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"state":         {"first"},
	}
	rec1 := s.doRequest(form, "web_client", "secret")
	require.Equal(t, http.StatusCreated, rec1.Code)
	resp1 := s.parsePARResponse(rec1)

	form.Set("state", "second")
	rec2 := s.doRequest(form, "web_client", "secret")
	require.Equal(t, http.StatusCreated, rec2.Code)
	resp2 := s.parsePARResponse(rec2)

	assert.NotEqual(t, resp1.RequestURI, resp2.RequestURI)

	entry1 := s.storage.store[resp1.RequestURI]
	entry2 := s.storage.store[resp2.RequestURI]
	assert.Equal(t, "first", entry1.authReq.State)
	assert.Equal(t, "second", entry2.authReq.State)
}

func TestPushedAuthRequest_CrossClientRequestURIRejected(t *testing.T) {
	s := newPARTestSetup(t)

	webForm := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(webForm, "web_client", "secret")
	require.Equal(t, http.StatusCreated, rec.Code)
	resp := s.parsePARResponse(rec)

	_, err := s.storage.PushedAuthRequestByURI(context.Background(), "native_client", resp.RequestURI)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_id mismatch")
}

func TestPushedAuthRequest_StorageError(t *testing.T) {
	s := newPARTestSetup(t)
	s.storage.forceErr = errors.New("database connection lost")

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "server_error")
}

func TestPushedAuthRequest_MaxAgeAndACRValuesPreserved(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"max_age":       {"3600"},
		"acr_values":    {"urn:mace:incommon:iap:silver"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	require.Equal(t, http.StatusCreated, rec.Code)

	resp := s.parsePARResponse(rec)
	entry, ok := s.storage.store[resp.RequestURI]
	require.True(t, ok)
	require.NotNil(t, entry.authReq.MaxAge)
	assert.Equal(t, uint(3600), *entry.authReq.MaxAge)
	assert.Contains(t, entry.authReq.ACRValues, "urn:mace:incommon:iap:silver")
}

func TestPushedAuthRequest_LoginHintPreserved(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
		"login_hint":    {"user@example.com"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	require.Equal(t, http.StatusCreated, rec.Code)

	resp := s.parsePARResponse(rec)
	entry, ok := s.storage.store[resp.RequestURI]
	require.True(t, ok)
	assert.Equal(t, "user@example.com", entry.authReq.LoginHint)
}

func TestPushedAuthRequest_CodeChallengeParamsStored(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":             {"web_client"},
		"redirect_uri":          {"https://registered.com/callback"},
		"response_type":         {"code"},
		"scope":                 {"openid"},
		"code_challenge":        {"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"},
		"code_challenge_method": {"S256"},
	}
	rec := s.doRequest(form, "web_client", "secret")

	require.Equal(t, http.StatusCreated, rec.Code)

	resp := s.parsePARResponse(rec)
	entry, ok := s.storage.store[resp.RequestURI]
	require.True(t, ok)
	assert.Equal(t, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", entry.authReq.CodeChallenge)
	assert.Equal(t, oidc.CodeChallengeMethodS256, entry.authReq.CodeChallengeMethod)
}

func TestPushedAuthRequest_ExpiredRequestURIRejected(t *testing.T) {
	s := newPARTestSetup(t)

	form := url.Values{
		"client_id":     {"web_client"},
		"redirect_uri":  {"https://registered.com/callback"},
		"response_type": {"code"},
		"scope":         {"openid"},
	}
	rec := s.doRequest(form, "web_client", "secret")
	require.Equal(t, http.StatusCreated, rec.Code)
	resp := s.parsePARResponse(rec)

	delete(s.storage.store, resp.RequestURI)

	_, err := s.storage.PushedAuthRequestByURI(context.Background(), "web_client", resp.RequestURI)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid or expired request_uri")
}
