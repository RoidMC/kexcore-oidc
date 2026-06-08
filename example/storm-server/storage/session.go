// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// clientSession tracks a client's session for back-channel logout.
type clientSession struct {
	clientID string
	sid      string
}

// =================================================================
// storm.SessionStore
// =================================================================

func (s *Storage) TerminateSession(_ context.Context, userID, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Remove the user's session so prompt=none returns login_required.
	delete(s.sessions, userID)

	for id, token := range s.tokens {
		if token.ApplicationID == clientID && token.Subject == userID {
			delete(s.tokens, id)
		}
	}
	for id, token := range s.refreshTokens {
		if token.ApplicationID == clientID && token.UserID == userID {
			delete(s.refreshTokens, id)
		}
	}

	// Remove client session for back-channel logout tracking.
	if clients, ok := s.clientSessions[userID]; ok {
		delete(clients, clientID)
		if len(clients) == 0 {
			delete(s.clientSessions, userID)
		}
	}

	return nil
}

// RecordClientSession records that a client has an active session for a subject.
// Call this when issuing tokens to a client.
func (s *Storage) RecordClientSession(subject, clientID, sid string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.clientSessions[subject] == nil {
		s.clientSessions[subject] = make(map[string]*clientSession)
	}
	s.clientSessions[subject][clientID] = &clientSession{
		clientID: clientID,
		sid:      sid,
	}
}

// RemoveClientSession removes a client session for a subject.
func (s *Storage) RemoveClientSession(subject, clientID string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if clients, ok := s.clientSessions[subject]; ok {
		delete(clients, clientID)
		if len(clients) == 0 {
			delete(s.clientSessions, subject)
		}
	}
}

// ClientsForSession implements storm.BackChannelStore.
// Returns all clients that have active sessions for the given subject.
// If sid is provided, only returns clients with matching session ID.
func (s *Storage) ClientsForSession(_ context.Context, sub, sid string) ([]storm.Client, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	clients, ok := s.clientSessions[sub]
	if !ok {
		return nil, nil
	}

	var result []storm.Client
	for _, cs := range clients {
		// If sid is specified, only return clients with matching session
		if sid != "" && cs.sid != sid {
			continue
		}
		if client, exists := s.clients[cs.clientID]; exists {
			result = append(result, client)
		}
	}
	return result, nil
}

// GetSession implements authorization.SessionProvider.
// It checks whether the given subject has an active session and
// returns the original authentication time.
func (s *Storage) GetSession(_ context.Context, _ *http.Request, _ string) (string, time.Time, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	for subj, authTime := range s.sessions {
		if !authTime.IsZero() {
			return subj, authTime, true
		}
	}
	return "", time.Time{}, false
}

// CreateSession records a subject as having an active session.
func (s *Storage) CreateSession(subject string, authTime time.Time) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[subject] = authTime
}

// =================================================================
// Login support
// =================================================================

func (s *Storage) CheckUsernamePassword(username, password, id string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	request, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("request not found")
	}

	user := s.userStore.GetUserByUsername(username)
	if user != nil && user.Password == password {
		request.UserID = user.ID
		request.done = true
		request.authTime = time.Now()
		if len(request.ACRValues) > 0 {
			request.acr = request.ACRValues[0]
		}
		s.sessions[user.ID] = request.authTime
		return nil
	}
	return fmt.Errorf("invalid username or password")
}

// CompleteAuthRequest implements storm.AutoCompleteAuthRequest.
// It marks an auth request as done with the given subject and
// the original authentication time, without going through the
// login UI. Used for prompt=none with active sessions.
func (s *Storage) CompleteAuthRequest(_ context.Context, id string, subject string, authTime time.Time) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	request, ok := s.authRequests[id]
	if !ok {
		return fmt.Errorf("auth request not found: %s", id)
	}
	if request.done {
		return fmt.Errorf("auth request already completed: %s", id)
	}
	request.UserID = subject
	request.done = true
	request.authTime = authTime
	if len(request.ACRValues) > 0 {
		request.acr = request.ACRValues[0]
	}
	return nil
}
