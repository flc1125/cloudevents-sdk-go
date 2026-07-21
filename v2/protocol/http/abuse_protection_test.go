/*
 Copyright 2021 The CloudEvents Authors
 SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestValidateOriginPrefixBypass is a regression test for a bypass in
// Protocol.validateOrigin: it used to accept any request origin that merely
// started with an allowed origin (via strings.HasPrefix), letting an
// attacker who controls a hostname like "trusted.example.com.attacker.tld"
// pass validation against an allow-list entry of "trusted.example.com".
// See advisory-04-webhook-origin-prefix-bypass.md.
func TestValidateOriginPrefixBypass(t *testing.T) {
	tests := []struct {
		name          string
		allowedOrigin string
		requestOrigin string
		wantOK        bool
	}{
		{
			name:          "exact match is allowed",
			allowedOrigin: "trusted.example.com",
			requestOrigin: "trusted.example.com",
			wantOK:        true,
		},
		{
			name:          "subdomain is allowed",
			allowedOrigin: "trusted.example.com",
			requestOrigin: "sub.trusted.example.com",
			wantOK:        true,
		},
		{
			name:          "wildcard is allowed",
			allowedOrigin: "*",
			requestOrigin: "anything.attacker.tld",
			wantOK:        true,
		},
		{
			name:          "suffix bypass is rejected",
			allowedOrigin: "trusted.example.com",
			requestOrigin: "trusted.example.com.attacker.tld",
			wantOK:        false,
		},
		{
			name:          "concatenated bypass is rejected",
			allowedOrigin: "trusted.example.com",
			requestOrigin: "trusted.example.comevil.net",
			wantOK:        false,
		},
		{
			name:          "userinfo-style bypass is rejected",
			allowedOrigin: "trusted.example.com",
			requestOrigin: "trusted.example.com:9999@evil",
			wantOK:        false,
		},
		{
			name:          "unrelated origin is rejected",
			allowedOrigin: "trusted.example.com",
			requestOrigin: "evil.tld",
			wantOK:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &Protocol{WebhookConfig: &WebhookConfig{AllowedOrigins: []string{tt.allowedOrigin}}}
			r, err := http.NewRequest(http.MethodOptions, "/", nil)
			require.NoError(t, err)
			r.Header.Set("WebHook-Request-Origin", tt.requestOrigin)

			allowed, ok := p.ValidateRequestOrigin(r)
			require.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				require.Equal(t, tt.allowedOrigin, allowed)
			}
		})
	}
}

// TestHostMatchesOrigin is a unit test for the host/origin allow-list
// matching logic used by validateCallbackURL.
func TestHostMatchesOrigin(t *testing.T) {
	tests := []struct {
		name            string
		host            string
		validatedOrigin string
		want            bool
	}{
		{"exact match", "trusted.example.com", "trusted.example.com", true},
		{"subdomain match", "sub.trusted.example.com", "trusted.example.com", true},
		{"wildcard allows anything", "anything.attacker.tld", "*", true},
		{"suffix bypass is rejected", "trusted.example.com.attacker.tld", "trusted.example.com", false},
		{"concatenated bypass is rejected", "trusted.example.comevil.net", "trusted.example.com", false},
		{"unrelated host is rejected", "evil.tld", "trusted.example.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, hostMatchesOrigin(tt.host, tt.validatedOrigin))
		})
	}
}

// TestValidateCallbackURL is a unit-level regression test for the SSRF fix
// in validateCallbackURL: WebHook-Request-Callback must use http/https, its
// host must match (or be a subdomain of) the validated origin unless that
// origin is the wildcard "*", and its resolved address must never be
// loopback/private/link-local/unspecified/multicast. Literal IP addresses
// are used throughout so the test never performs a real DNS lookup.
// See advisory-05-webhook-callback-ssrf.md.
func TestValidateCallbackURL(t *testing.T) {
	tests := []struct {
		name            string
		callback        string
		validatedOrigin string
		wantErr         bool
	}{
		{
			name:            "matching host and public IP is allowed",
			callback:        "http://93.184.216.34/ack",
			validatedOrigin: "93.184.216.34",
			wantErr:         false,
		},
		{
			name:            "wildcard origin allows public IP",
			callback:        "https://93.184.216.34/ack",
			validatedOrigin: "*",
			wantErr:         false,
		},
		{
			name:            "wildcard origin still blocks loopback destinations",
			callback:        "http://127.0.0.1:8080/internal",
			validatedOrigin: "*",
			wantErr:         true,
		},
		{
			name:            "wildcard origin still blocks cloud metadata address",
			callback:        "http://169.254.169.254/latest/meta-data",
			validatedOrigin: "*",
			wantErr:         true,
		},
		{
			name:            "wildcard origin still blocks private RFC1918 address",
			callback:        "http://10.0.0.5/admin",
			validatedOrigin: "*",
			wantErr:         true,
		},
		{
			name:            "host mismatch with validated origin is rejected",
			callback:        "http://127.0.0.1:8080/internal",
			validatedOrigin: "trusted.example.com",
			wantErr:         true,
		},
		{
			name:            "disallowed scheme is rejected",
			callback:        "file:///etc/passwd",
			validatedOrigin: "*",
			wantErr:         true,
		},
		{
			name:            "unparsable URL is rejected",
			callback:        "http://%zz",
			validatedOrigin: "*",
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := validateCallbackURL(tt.callback, tt.validatedOrigin)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// TestOptionsHandlerCallbackSSRFBlocked is an end-to-end regression test
// reproducing the advisory's SSRF PoC: an attacker spoofs
// WebHook-Request-Origin to pass the (attacker-controlled) origin check and
// supplies an internal callback URL. The OPTIONS handler must not issue any
// outbound request to that internal server.
func TestOptionsHandlerCallbackSSRFBlocked(t *testing.T) {
	var hit string
	var mu sync.Mutex
	internal := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hit = fmt.Sprintf("%s %s", r.Method, r.URL.String())
		mu.Unlock()
	}))
	defer internal.Close()

	p, err := New(WithDefaultOptionsHandlerFunc(
		[]string{"POST"}, 100, []string{"trusted.example.com"}, true /* AutoACKCallback */))
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodOptions, "http://victim/", nil)
	req.Header.Set("WebHook-Request-Origin", "trusted.example.com")
	req.Header.Set("WebHook-Request-Callback", internal.URL+"/internal/admin?x=1")
	rw := httptest.NewRecorder()
	p.ServeHTTP(rw, req)

	// Give any (incorrectly) spawned background goroutine a chance to fire.
	time.Sleep(200 * time.Millisecond)

	mu.Lock()
	defer mu.Unlock()
	require.Empty(t, hit, "internal server must never receive the SSRF callback")
	require.Equal(t, http.StatusBadRequest, rw.Code)
}
