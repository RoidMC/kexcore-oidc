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
	subject    string
	expires    time.Time
	scopes     []string
	done       bool
	denied     bool
}

type DeviceAuthStore struct {
	lock    sync.Mutex
	entries map[string]*deviceAuth // deviceCode -> entry
	byCode  map[string]*deviceAuth // userCode -> entry
}

func (d *DeviceAuthStore) StoreDeviceAuthorization(_ context.Context, clientID, deviceCode, userCode string, expires time.Time, scopes []string) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry := &deviceAuth{
		clientID:   clientID,
		deviceCode: deviceCode,
		userCode:   userCode,
		expires:    expires,
		scopes:     scopes,
	}
	d.entries[deviceCode] = entry
	d.byCode[userCode] = entry
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
		DeviceCode: entry.deviceCode,
		ClientID:   entry.clientID,
		UserCode:   entry.userCode,
		Subject:    entry.subject,
		Scopes:     entry.scopes,
		Done:       entry.done,
		Denied:     entry.denied,
		Expires:    entry.expires,
	}, nil
}

func (d *DeviceAuthStore) GetDeviceAuthorizationByUserCode(_ context.Context, userCode string) (*storm.DeviceAuthorizationState, error) {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry, ok := d.byCode[userCode]
	if !ok {
		return nil, fmt.Errorf("device authorization not found")
	}
	return &storm.DeviceAuthorizationState{
		DeviceCode: entry.deviceCode,
		ClientID:   entry.clientID,
		UserCode:   entry.userCode,
		Subject:    entry.subject,
		Scopes:     entry.scopes,
		Done:       entry.done,
		Denied:     entry.denied,
		Expires:    entry.expires,
	}, nil
}

func (d *DeviceAuthStore) ApproveDeviceAuthorization(_ context.Context, userCode, subject string) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry, ok := d.byCode[userCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	entry.done = true
	entry.subject = subject
	return nil
}

func (d *DeviceAuthStore) DenyDeviceAuthorization(_ context.Context, userCode string) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry, ok := d.byCode[userCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	entry.denied = true
	return nil
}
