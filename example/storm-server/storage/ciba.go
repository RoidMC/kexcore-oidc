// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/pkg/storm"
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
