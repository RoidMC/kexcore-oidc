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

// sessionInfo holds the authentication time and session ID for an active session.
type sessionInfo struct {
	subject  string
	clientID string // 新增：记录所属client，防止session串用
	authTime time.Time
	sid      string
	expiry   time.Time
}

// =================================================================
// storm.SessionStore
// =================================================================

func (s *Storage) TerminateSession(_ context.Context, userID, clientID string) error {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Remove the user's sessions so prompt=none returns login_required.
	// Since sessions are keyed by session ID, we need to find and remove
	// all sessions belonging to this user.
	for sid, info := range s.sessions {
		if info.subject == userID {
			delete(s.sessions, sid)
		}
	}

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
// Only records sessions for clients that have a backchannel_logout_uri configured,
// since only those clients need to be notified on logout.
func (s *Storage) RecordClientSession(subject, clientID, sid string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	// Only track sessions for clients with backchannel_logout_uri
	client, ok := s.clients[clientID]
	if !ok {
		return
	}
	if client.BackChannelLogoutURI() == "" {
		return
	}
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
// returns the original authentication time and session ID.
// The session is identified by the "session_id" cookie in the request.
func (s *Storage) GetSession(_ context.Context, r *http.Request, clientID string) (string, time.Time, string, bool) {
	cookie, err := r.Cookie("session_id")
	if err != nil {
		return "", time.Time{}, "", false
	}

	s.lock.Lock()
	defer s.lock.Unlock()

	info, ok := s.sessions[cookie.Value]
	if !ok {
		return "", time.Time{}, "", false
	}

	// 检查client_id是否匹配，防止session串用
	if clientID != "" && info.clientID != clientID {
		return "", time.Time{}, "", false
	}

	// Check if session has expired
	if !info.expiry.IsZero() && time.Now().After(info.expiry) {
		delete(s.sessions, cookie.Value)
		return "", time.Time{}, "", false
	}

	return info.subject, info.authTime, info.sid, true
}

// CreateSession records a subject as having an active session.
// The session is stored with the session ID as the key.
// Default session expiry is 24 hours.
func (s *Storage) CreateSession(subject string, authTime time.Time, sid string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[sid] = &sessionInfo{
		subject:  subject,
		authTime: authTime,
		sid:      sid,
		expiry:   time.Now().Add(24 * time.Hour),
	}
}

// CreateSessionWithClient records a subject as having an active session for a specific client.
// The session is stored with the session ID as the key.
// Default session expiry is 24 hours.
func (s *Storage) CreateSessionWithClient(subject, clientID string, authTime time.Time, sid string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	s.sessions[sid] = &sessionInfo{
		subject:  subject,
		clientID: clientID,
		authTime: authTime,
		sid:      sid,
		expiry:   time.Now().Add(24 * time.Hour),
	}
}

// GetSessionBySubject returns the most recent active session for a given subject.
// Used by prompt=none when the caller provides id_token_hint or login_hint
// instead of a session cookie.
// If clientID is provided, only returns sessions for that client.
func (s *Storage) GetSessionBySubject(subject string, clientID ...string) (authTime time.Time, sid string, ok bool) {
	s.lock.Lock()
	defer s.lock.Unlock()

	var found *sessionInfo
	for _, info := range s.sessions {
		if info.subject != subject {
			continue
		}
		// 如果指定了clientID，只返回该client的session
		if len(clientID) > 0 && clientID[0] != "" && info.clientID != clientID[0] {
			continue
		}
		if !info.expiry.IsZero() && time.Now().After(info.expiry) {
			continue
		}
		if found == nil || info.authTime.After(found.authTime) {
			found = info
		}
	}
	if found == nil {
		return time.Time{}, "", false
	}
	return found.authTime, found.sid, true
}

// GetAuthRequestSessionID returns the session ID for the given auth request.
// Used by the login handler to set the session_id cookie after successful login.
func (s *Storage) GetAuthRequestSessionID(id string) string {
	s.lock.Lock()
	defer s.lock.Unlock()
	if req, ok := s.authRequests[id]; ok {
		return req.sessionID
	}
	return ""
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
		// Rebuild extra ID token claims now that the user is known.
		// At CreateAuthRequest time the user was nil (not logged in yet),
		// so these were empty.
		request.extraIDTokenClaims = buildIDTokenClaims(request.Scopes, request.Claims, user, request.ResponseType)
		// Store session with session ID as key (not subject)
		// 记录clientID，防止不同client的session串用
		s.sessions[request.sessionID] = &sessionInfo{
			subject:  user.ID,
			clientID: request.ApplicationID,
			authTime: request.authTime,
			sid:      request.sessionID,
			expiry:   time.Now().Add(24 * time.Hour),
		}
		return nil
	}
	return fmt.Errorf("invalid username or password")
}

// CompleteAuthRequest implements storm.AutoCompleteAuthRequest.
// It marks an auth request as done with the given subject and
// the original authentication time, without going through the
// login UI. Used for prompt=none with active sessions.
func (s *Storage) CompleteAuthRequest(_ context.Context, id string, subject string, authTime time.Time, sid string) error {
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
	request.sessionID = sid
	if len(request.ACRValues) > 0 {
		request.acr = request.ACRValues[0]
	}
	return nil
}
