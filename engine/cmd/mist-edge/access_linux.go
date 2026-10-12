//go:build linux

package main

import (
	"github.com/sanderstripa/vpn/mist/internal/accesspolicy"
	"net/http"
	"net/netip"
	"time"
)

type accessContextKey struct{}
type accessContext struct {
	prefix netip.Prefix
	policy *accesspolicy.Store
	token  string
}

func authorizedPrefix(r *http.Request) netip.Prefix {
	v, _ := r.Context().Value(accessContextKey{}).(accessContext)
	return v.prefix
}

// Closing the actual stream terminates an already connected revoked device.
func watchAccess(r *http.Request, closeStream func()) func() {
	v, _ := r.Context().Value(accessContextKey{}).(accessContext)
	if v.policy == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		tick := time.NewTicker(500 * time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-done:
				return
			case <-r.Context().Done():
				return
			case <-tick.C:
				k, err := v.policy.Lookup(v.token, time.Now())
				if err != nil || k.Address != v.prefix.Addr().String() {
					closeStream()
					return
				}
			}
		}
	}()
	return func() { close(done) }
}
