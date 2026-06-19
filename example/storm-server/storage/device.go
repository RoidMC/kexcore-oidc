// SPDX-License-Identifier: Apache-2.0
//
// Copyright 2026 RoidMC Studios

package storage

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/roidmc/kexcore-oidc/v2/pkg/storm"
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
	lastPoll   time.Time // last poll time for slow_down detection
	interval   int       // current polling interval in seconds
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
		LastPoll:   entry.lastPoll,
		Interval:   entry.interval,
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
		LastPoll:   entry.lastPoll,
		Interval:   entry.interval,
	}, nil
}

func (d *DeviceAuthStore) UpdateDeviceAuthorizationPoll(_ context.Context, _, deviceCode string, lastPoll time.Time) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry, ok := d.entries[deviceCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	entry.lastPoll = lastPoll
	return nil
}

func (d *DeviceAuthStore) UpdateDeviceAuthorizationInterval(_ context.Context, _, deviceCode string, increment int) error {
	d.lock.Lock()
	defer d.lock.Unlock()
	entry, ok := d.entries[deviceCode]
	if !ok {
		return fmt.Errorf("device authorization not found")
	}
	entry.interval += increment
	return nil
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

// cleanupExpired removes expired device authorization entries.
func (d *DeviceAuthStore) cleanupExpired() {
	d.lock.Lock()
	defer d.lock.Unlock()
	now := time.Now()
	for code, entry := range d.entries {
		if now.After(entry.expires) {
			delete(d.entries, code)
			delete(d.byCode, entry.userCode)
		}
	}
}

// StartCleanup starts a background goroutine that cleans up expired entries every interval.
func (d *DeviceAuthStore) StartCleanup(interval time.Duration) *time.Ticker {
	ticker := time.NewTicker(interval)
	go func() {
		for range ticker.C {
			d.cleanupExpired()
		}
	}()
	return ticker
}
