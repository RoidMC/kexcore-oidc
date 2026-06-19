// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

// Compile-time interface check.
var _ storm.CIBAStore = (*Storage)(nil)

// =================================================================
// storm.CIBAStore (Client-Initiated Backchannel Authentication)
// =================================================================

func (s *Storage) StoreCIBARequest(_ context.Context, req *storm.CIBARequest) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cibaRequests == nil {
		s.cibaRequests = make(map[string]*storm.CIBARequest)
	}
	s.cibaRequests[req.AuthReqID] = req
	return nil
}

func (s *Storage) GetCIBARequestByAuthReqID(_ context.Context, authReqID string) (*storm.CIBARequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cibaRequests == nil {
		return nil, protocol.ErrAuthorizationPending()
	}
	req, ok := s.cibaRequests[authReqID]
	if !ok {
		return nil, protocol.ErrAuthorizationPending()
	}
	return req, nil
}

func (s *Storage) GetPendingCIBARequests(_ context.Context, subject string) ([]*storm.CIBARequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	var result []*storm.CIBARequest
	if s.cibaRequests == nil {
		return result, nil
	}
	for _, req := range s.cibaRequests {
		if req.Subject == subject && req.Status == protocol.CIBAStatusPending {
			result = append(result, req)
		}
	}
	return result, nil
}

func (s *Storage) UpdateCIBARequestStatus(_ context.Context, authReqID string, status protocol.CIBAStatus, approvedScopes []string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cibaRequests == nil {
		return fmt.Errorf("ciba request not found: %s", authReqID)
	}
	req, ok := s.cibaRequests[authReqID]
	if !ok {
		return fmt.Errorf("ciba request not found: %s", authReqID)
	}
	req.Status = status
	req.ApprovedScopes = approvedScopes
	return nil
}

func (s *Storage) DeleteCIBARequest(_ context.Context, authReqID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cibaRequests != nil {
		delete(s.cibaRequests, authReqID)
	}
	return nil
}

func (s *Storage) UpdateCIBAPoll(_ context.Context, authReqID string, lastPoll time.Time) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cibaRequests == nil {
		return fmt.Errorf("ciba request not found: %s", authReqID)
	}
	req, ok := s.cibaRequests[authReqID]
	if !ok {
		return fmt.Errorf("ciba request not found: %s", authReqID)
	}
	req.LastPoll = lastPoll
	return nil
}

func (s *Storage) UpdateCIBAInterval(_ context.Context, authReqID string, increment int) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.cibaRequests == nil {
		return fmt.Errorf("ciba request not found: %s", authReqID)
	}
	req, ok := s.cibaRequests[authReqID]
	if !ok {
		return fmt.Errorf("ciba request not found: %s", authReqID)
	}
	req.Interval += increment
	return nil
}

// Compile-time interface check for CIBANotificationCallback.
var _ storm.CIBANotificationCallback = (*Storage)(nil)

// OnCIBAStatusChange sends a ping notification to the client's notification endpoint
// when a CIBA request is approved or denied (CIBA Core 1.0 §10).
func (s *Storage) OnCIBAStatusChange(_ context.Context, req *storm.CIBARequest) error {
	if req.DeliveryMode != protocol.CIBAModePing {
		slog.Info("[DEBUG] ciba notify: skip, not ping mode", "delivery_mode", req.DeliveryMode)
		return nil
	}
	if req.ClientNotificationToken == "" {
		slog.Info("[DEBUG] ciba notify: skip, no client_notification_token")
		return nil
	}

	// Look up client notification endpoint
	s.lock.Lock()
	client, ok := s.clients[req.ClientID]
	s.lock.Unlock()
	if !ok {
		slog.Warn("[DEBUG] ciba notify: client not found", "client_id", req.ClientID)
		return fmt.Errorf("client not found: %s", req.ClientID)
	}
	endpoint := client.NotificationEndpoint()
	if endpoint == "" {
		slog.Warn("[DEBUG] ciba notify: client_notification_endpoint not configured", "client_id", req.ClientID)
		return fmt.Errorf("client_notification_endpoint not configured for client: %s", req.ClientID)
	}

	slog.Info("[DEBUG] ciba notify: sending ping notification",
		"auth_req_id", req.AuthReqID,
		"client_id", req.ClientID,
		"endpoint", endpoint,
		"status", req.Status,
	)

	// Send POST to client_notification_endpoint
	// CIBA Core 1.0 §10.1: include client_notification_token as Bearer token
	// Include auth_req_id in body for spec compliance
	body := strings.NewReader(fmt.Sprintf(`{"auth_req_id":"%s"}`, req.AuthReqID))
	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, endpoint, body)
	if err != nil {
		slog.Warn("[DEBUG] ciba notify: failed to create request", "error", err)
		return fmt.Errorf("failed to create notification request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+req.ClientNotificationToken)
	httpReq.Header.Set("Content-Type", "application/json")

	httpClient := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		// CIBA Core 1.0 §10.1: the server MUST NOT follow redirect responses
		// from the client_notification_endpoint.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := httpClient.Do(httpReq)
	if err != nil {
		slog.Warn("[DEBUG] ciba notify: request failed", "error", err, "endpoint", endpoint)
		// CIBA Core 1.0 §10.1: notification failures should not affect the flow
		return nil
	}
	defer resp.Body.Close()

	slog.Info("[DEBUG] ciba notify: notification sent",
		"auth_req_id", req.AuthReqID,
		"status_code", resp.StatusCode,
	)

	return nil
}
