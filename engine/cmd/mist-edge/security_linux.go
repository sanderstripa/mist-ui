//go:build linux

package main

import (
	"context"
	"crypto/subtle"
	"github.com/sanderstripa/vpn/mist/internal/accesspolicy"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/auth"
	"github.com/sanderstripa/vpn/mist/internal/config"
	"github.com/sanderstripa/vpn/mist/internal/ratelimit"
)

type edgeAuthorizer struct {
	policy           *accesspolicy.Store
	fallback         netip.Prefix
	staticToken      string
	secret           string
	limiter          *ratelimit.Limiter
	handshakeLimiter *ratelimit.Limiter
}

func newEdgeAuthorizer(cfg config.ServerConfig) *edgeAuthorizer {
	fallback, _ := netip.ParsePrefix(cfg.ClientCIDR)
	return &edgeAuthorizer{
		policy: &accesspolicy.Store{Path: cfg.AccessPolicyFile}, fallback: fallback,
		staticToken:      cfg.Token,
		secret:           cfg.TokenSecret,
		limiter:          ratelimit.New(cfg.AuthRateLimitPerMinute, time.Minute),
		handshakeLimiter: ratelimit.New(cfg.QUICRetryThresholdPerMinute, time.Minute),
	}
}

func (a *edgeAuthorizer) Valid(r *http.Request) bool {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		token := strings.TrimPrefix(h, prefix)
		if a.policy.Path != "" {
			k, err := a.policy.Lookup(token, time.Now())
			if err != nil {
				return false
			}
			ip, _ := netip.ParseAddr(k.Address)
			*r = *r.WithContext(context.WithValue(r.Context(), accessContextKey{}, accessContext{netip.PrefixFrom(ip, 32), a.policy, token}))
			return true
		}
		*r = *r.WithContext(context.WithValue(r.Context(), accessContextKey{}, accessContext{a.fallback, nil, ""}))
		if a.staticToken != "" && len(token) == len(a.staticToken) && subtle.ConstantTimeCompare([]byte(token), []byte(a.staticToken)) == 1 {
			return true
		}
		if a.secret != "" {
			if _, err := auth.Verify(a.secret, token, time.Now()); err == nil {
				return true
			}
		}
	}
	return false
}

func (a *edgeAuthorizer) AllowPublic(r *http.Request) bool {
	return a.limiter.Allow(remoteHost(r.RemoteAddr), time.Now())
}

// VerifyQUICSource is used before HTTP is available. Under ordinary load it
// doesn't add a round-trip. A source that creates an unusual number of fresh
// QUIC handshakes is switched to QUIC Retry address validation, making spoofed
// source attacks substantially more expensive without changing normal traffic.
func (a *edgeAuthorizer) VerifyQUICSource(addr net.Addr) bool {
	if addr == nil {
		return true
	}
	return !a.handshakeLimiter.Allow(remoteHost(addr.String()), time.Now())
}

func remoteHost(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}
