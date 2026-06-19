package storage

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/protocol"
	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
)

// Compile-time interface check.
var _ storm.PARStore = (*PARStore)(nil)

// PARStore implements storm.PARStore for in-memory pushed authorization requests.
type PARStore struct {
	lock   sync.Mutex
	reqs   map[string]*parEntry // requestURI -> entry
	client map[string][]*parEntry // clientID -> entries
}

type parEntry struct {
	clientID   string
	requestURI string
	authReq    *protocol.AuthRequest
	expires    time.Time
}

func NewPARStore() *PARStore {
	return &PARStore{
		reqs:   make(map[string]*parEntry),
		client: make(map[string][]*parEntry),
	}
}

func (s *PARStore) StorePushedAuthRequest(_ context.Context, clientID string, req *protocol.AuthRequest, lifetime time.Duration) (string, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	requestURI := "urn:ietf:params:oauth:request_uri:" + generatePARCode(24)
	entry := &parEntry{
		clientID:   clientID,
		requestURI: requestURI,
		authReq:    req,
		expires:    time.Now().Add(lifetime),
	}
	s.reqs[requestURI] = entry
	s.client[clientID] = append(s.client[clientID], entry)
	return requestURI, nil
}

func (s *PARStore) GetPushedAuthRequest(_ context.Context, requestURI string) (*protocol.AuthRequest, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	entry, ok := s.reqs[requestURI]
	if !ok {
		return nil, fmt.Errorf("pushed auth request not found: %s", requestURI)
	}
	if time.Now().After(entry.expires) {
		delete(s.reqs, requestURI)
		return nil, fmt.Errorf("pushed auth request expired: %s", requestURI)
	}
	return entry.authReq, nil
}

func generatePARCode(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand.Read failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
