// SPDX-License-Identifier: Apache-2.0
//
// Copyright Zitadel
// Modifications Copyright 2026 RoidMC Studios

package http

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
)

var DefaultHTTPClient = &http.Client{
	Timeout: 30 * time.Second,
}

type Decoder interface {
	Decode(dst any, src map[string][]string) error
}

type Encoder interface {
	Encode(src any, dst map[string][]string) error
}

type FormAuthorization func(url.Values)
type RequestAuthorization func(*http.Request)

// AuthorizeBasic returns a RequestAuthorization that sets HTTP Basic
// authentication on the request using the provided user and password.
//
// Per RFC 6749 §2.3.1, OAuth 2.0 clients SHOULD encode client_id and
// client_secret via application/x-www-form-urlencoded before applying
// Basic auth:
//
//	base64(formUrlEncode(client_id) + ":" + formUrlEncode(client_secret))
//
// This is correct per spec, and some authorization servers (e.g. Keycloak)
// strictly URL-decode credentials on receipt. However, many other servers
// (Auth0, Okta, Google, GitHub) accept raw credentials directly, and
// double-encoding secrets containing '@' or ':' causes authentication
// failures with those providers.
//
// We pass raw values to SetBasicAuth for broader real-world compatibility.
// Downstream callers that need strict RFC compliance should use their own
// RequestAuthorization.
//
// To restore RFC-compliant behaviour, replace the body with:
//
//	req.SetBasicAuth(url.QueryEscape(user), url.QueryEscape(password))
func AuthorizeBasic(user, password string) RequestAuthorization {
	return func(req *http.Request) {
		req.SetBasicAuth(user, password)
	}
}

func FormRequest(ctx context.Context, endpoint string, request any, encoder Encoder, authFn any) (*http.Request, error) {
	form := url.Values{}
	if err := encoder.Encode(request, form); err != nil {
		return nil, err
	}
	if fn, ok := authFn.(FormAuthorization); ok {
		fn(form)
	}
	body := strings.NewReader(form.Encode())
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, body)
	if err != nil {
		return nil, err
	}
	if fn, ok := authFn.(RequestAuthorization); ok {
		fn(req)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req, nil
}

// This part of the design references KexCore's Webhook Engine security design
//
//	Ref: https://github.com/RoidMC/KexCore/blob/main/core/internal/event/dispatcher.go
const defaultMaxRespBodySize = 1 << 20 // 1 MB

func HttpRequest(client *http.Client, req *http.Request, response any) error {
	if client == nil {
		return fmt.Errorf("http: client must not be nil")
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, defaultMaxRespBodySize))
	if err != nil {
		return fmt.Errorf("unable to read response body: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		var oidcErr protocol.Error
		err = json.Unmarshal(body, &oidcErr)
		if err != nil || oidcErr.ErrorType == "" {
			log.Printf("[kexcore-oidc/http] http status not ok: %s (body omitted for security)", resp.Status)
			return fmt.Errorf("http status not ok: %s", resp.Status)
		}
		return &oidcErr
	}

	err = json.Unmarshal(body, response)
	if err != nil {
		return fmt.Errorf("failed to unmarshal response: %v", err)
	}
	return nil
}

func URLEncodeParams(resp any, encoder Encoder) (url.Values, error) {
	values := make(map[string][]string)
	err := encoder.Encode(resp, values)
	if err != nil {
		return nil, err
	}
	return values, nil
}

func StartServer(ctx context.Context, port string) {
	server := &http.Server{Addr: port}
	go func() {
		if err := server.ListenAndServe(); err != http.ErrServerClosed {
			log.Printf("[kexcore-oidc/http] ListenAndServe(): %v", err)
		}
	}()

	go func() {
		<-ctx.Done()
		ctxShutdown, cancelShutdown := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancelShutdown()
		if err := server.Shutdown(ctxShutdown); err != nil {
			log.Printf("[kexcore-oidc/http] Shutdown(): %v", err)
		}
	}()
}
