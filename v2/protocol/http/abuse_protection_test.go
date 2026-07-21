/*
 Copyright 2021 The CloudEvents Authors
 SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"net/http"
	"testing"

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
