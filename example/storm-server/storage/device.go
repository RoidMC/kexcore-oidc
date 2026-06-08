// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/roidmc/kexcore-oidc/pkg/storm"
)

// =================================================================
// DeviceAuthStore (optional)
// =================================================================

type deviceAuth struct {
	clientID   string
	deviceCode string
	userCode   string
	expires    time.Time
	scopes     []string
	done       bool
	denied     bool
}

type DeviceAuthStore struct {
	lock    sync.Mutex
	entries map[string]*deviceAuth
}

func (s *Storage) DeviceAuthStore() *DeviceAuthStore {
	return &DeviceAuthStore{entries: make(map[string]*deviceAuth)}
}

func (d *DeviceAuthStore) StoreDeviceAuthorization(_ context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	d.entries[deviceCode] = &deviceAuth{
		clientID:   clientID,
		deviceCode: deviceCode,
		userCode:   userCode,
		expires:    expires,
		scopes:     scopes,
	}
	return nil
}

func (d *DeviceAuthStore) GetDeviceAuthorizationState(_ context.Context, _, deviceCode string) (*storm.DeviceAuthorizationState, error) {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry, ok := d.entries[deviceCode]
	if !ok {
		return nil, fmt.Errorf("device authorization not found")
	}
	return &storm.DeviceAuthorizationState{
		ClientID: entry.clientID,
		Scopes:   entry.scopes,
		Done:     entry.done,
		Denied:   entry.denied,
		Expires:  entry.expires,
	}, nil
}
