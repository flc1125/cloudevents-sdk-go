/*
 Copyright 2021 The CloudEvents Authors
 SPDX-License-Identifier: Apache-2.0
*/

package http

import (
	"context"
	"fmt"
	cecontext "github.com/cloudevents/sdk-go/v2/context"
	"go.uber.org/zap"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type WebhookConfig struct {
	AllowedMethods  []string // defaults to POST
	AllowedRate     *int
	AutoACKCallback bool
	AllowedOrigins  []string
}

const (
	DefaultAllowedRate = 1000
	DefaultTimeout     = time.Second * 600
)

// TODO: implement rate limiting.
// Throttling is indicated by requests being rejected using HTTP status code 429 Too Many Requests.
// TODO: use this if Webhook Request Origin has been turned on.
// Inbound requests should be rejected if Allowed Origins is required by SDK.

func (p *Protocol) OptionsHandler(rw http.ResponseWriter, req *http.Request) {
	if req.Method != http.MethodOptions || p.WebhookConfig == nil {
		rw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	headers := make(http.Header)

	// The spec does not say we need to validate the origin, just the request origin.
	// After the handshake, we will validate the origin.
	origin, ok := p.ValidateRequestOrigin(req)
	if !ok {
		rw.WriteHeader(http.StatusBadRequest)
		return
	}
	headers.Set("WebHook-Allowed-Origin", origin)

	allowedRateRequired := false
	if _, ok := req.Header[http.CanonicalHeaderKey("WebHook-Request-Rate")]; ok {
		// must send WebHook-Allowed-Rate
		allowedRateRequired = true
	}

	if p.WebhookConfig.AllowedRate != nil {
		headers.Set("WebHook-Allowed-Rate", strconv.Itoa(*p.WebhookConfig.AllowedRate))
	} else if allowedRateRequired {
		headers.Set("WebHook-Allowed-Rate", strconv.Itoa(DefaultAllowedRate))
	}

	if len(p.WebhookConfig.AllowedMethods) > 0 {
		headers.Set("Allow", strings.Join(p.WebhookConfig.AllowedMethods, ", "))
	} else {
		headers.Set("Allow", http.MethodPost)
	}

	cb := req.Header.Get("WebHook-Request-Callback")
	if cb != "" {
		if p.WebhookConfig.AutoACKCallback {
			cbURL, err := validateCallbackURL(cb, origin)
			if err != nil {
				cecontext.LoggerFrom(req.Context()).Errorw("OPTIONS handler rejected web hook request callback.", zap.Error(err), zap.String("callback", cb))
				rw.WriteHeader(http.StatusBadRequest)
				return
			}

			go func() {
				reqAck, err := http.NewRequest(http.MethodPost, cbURL.String(), nil)
				if err != nil {
					cecontext.LoggerFrom(req.Context()).Errorw("OPTIONS handler failed to create http request attempting to ack callback.", zap.Error(err), zap.String("callback", cb))
					return
				}

				// Write out the headers.
				for k := range headers {
					reqAck.Header.Set(k, headers.Get(k))
				}

				_, err = http.DefaultClient.Do(reqAck)
				if err != nil {
					cecontext.LoggerFrom(req.Context()).Errorw("OPTIONS handler failed to ack callback.", zap.Error(err), zap.String("callback", cb))
					return
				}
			}()
			return
		} else {
			cecontext.LoggerFrom(req.Context()).Infof("ACTION REQUIRED: Please validate web hook request callback: %q", cb)
			// TODO: what to do pending https://github.com/cloudevents/spec/issues/617
			return
		}
	}

	// Write out the headers.
	for k := range headers {
		rw.Header().Set(k, headers.Get(k))
	}
}

func (p *Protocol) ValidateRequestOrigin(req *http.Request) (string, bool) {
	return p.validateOrigin(req.Header.Get("WebHook-Request-Origin"))
}

func (p *Protocol) ValidateOrigin(req *http.Request) (string, bool) {
	return p.validateOrigin(req.Header.Get("Origin"))
}

func (p *Protocol) validateOrigin(ro string) (string, bool) {
	cecontext.LoggerFrom(context.TODO()).Infow("Validating origin.", zap.String("origin", ro))

	for _, ao := range p.WebhookConfig.AllowedOrigins {
		if ao == "*" {
			return ao, true
		}
		// Require an exact match, or a match anchored at a DNS-label
		// boundary (e.g. "sub.trusted.example.com" is allowed by
		// "trusted.example.com", but "trusted.example.com.attacker.tld"
		// is not). A plain strings.HasPrefix check would let any origin
		// that merely starts with an allowed value bypass the allow-list.
		if ro == ao || strings.HasSuffix(ro, "."+ao) {
			return ao, true
		}
	}

	return ro, false
}

// validateCallbackURL validates a client-supplied WebHook-Request-Callback
// URL before the server is allowed to issue an outbound request to it. This
// guards against SSRF: without these checks an attacker could point the
// callback at internal services (loopback, RFC1918, link-local, cloud
// metadata endpoints, etc.) simply by spoofing the WebHook-Request-Origin
// header used for the (attacker-controlled) origin check.
//
// validatedOrigin is the allow-list entry that the request's origin matched
// (as returned by ValidateRequestOrigin). Unless that entry is the wildcard
// "*", the callback's host must equal, or be a subdomain of, the validated
// origin, which ties the callback destination to an operator-configured
// allow-list rather than to attacker-controlled input alone. Independently
// of that check, the callback is always rejected if its host is (or
// resolves to) a loopback, private, link-local, unspecified, or multicast
// address, since those are never legitimate public webhook destinations.
func validateCallbackURL(cb string, validatedOrigin string) (*url.URL, error) {
	u, err := url.Parse(cb)
	if err != nil {
		return nil, fmt.Errorf("invalid callback URL: %w", err)
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, fmt.Errorf("callback URL scheme %q is not allowed, only http and https are supported", u.Scheme)
	}

	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("callback URL is missing a host")
	}

	if !hostMatchesOrigin(host, validatedOrigin) {
		return nil, fmt.Errorf("callback host %q does not match the validated origin %q", host, validatedOrigin)
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve callback host %q: %w", host, err)
	}
	for _, ip := range ips {
		if isDisallowedCallbackIP(ip) {
			return nil, fmt.Errorf("callback host %q resolves to disallowed address %s", host, ip)
		}
	}

	return u, nil
}

// hostMatchesOrigin reports whether host is allowed as a webhook callback
// destination given the origin allow-list entry that the request's origin
// matched. The wildcard "*" allows any host; otherwise host must be exactly
// validatedOrigin or a subdomain of it.
func hostMatchesOrigin(host, validatedOrigin string) bool {
	return validatedOrigin == "*" || host == validatedOrigin || strings.HasSuffix(host, "."+validatedOrigin)
}

// isDisallowedCallbackIP reports whether ip is a loopback, private,
// link-local, unspecified, or multicast address that should never be a
// valid webhook callback destination.
func isDisallowedCallbackIP(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}
