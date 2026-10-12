package main

import (
	"sort"
	"sync"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/config"
)

type endpointHealthState struct {
	Failures      int
	Successes     uint64
	LastFailure   time.Time
	LastSuccess   time.Time
	CooldownUntil time.Time
	LastDial      time.Duration
}

var endpointHealth = struct {
	sync.Mutex
	m map[string]endpointHealthState
}{m: make(map[string]endpointHealthState)}

func endpointKey(ep config.EndpointConfig) string { return ep.Authority + "|" + ep.DialAddress + "|" + ep.Path }

func recordEndpointFailure(ep config.EndpointConfig, dial time.Duration) {
	endpointHealth.Lock()
	defer endpointHealth.Unlock()
	k := endpointKey(ep)
	s := endpointHealth.m[k]
	s.Failures++
	s.LastFailure = time.Now()
	s.LastDial = dial
	backoff := time.Duration(1<<min(s.Failures-1, 6)) * 5 * time.Second
	if backoff > 5*time.Minute { backoff = 5 * time.Minute }
	s.CooldownUntil = time.Now().Add(backoff)
	endpointHealth.m[k] = s
}

func recordEndpointSuccess(ep config.EndpointConfig, dial time.Duration) {
	endpointHealth.Lock()
	defer endpointHealth.Unlock()
	k := endpointKey(ep)
	s := endpointHealth.m[k]
	s.Successes++
	s.Failures = 0
	s.LastSuccess = time.Now()
	s.LastDial = dial
	s.CooldownUntil = time.Time{}
	endpointHealth.m[k] = s
}

func orderedEndpoints(eps []config.EndpointConfig) []config.EndpointConfig {
	if len(eps) < 2 { return append([]config.EndpointConfig(nil), eps...) }
	type scored struct {
		ep         config.EndpointConfig
		idx        int
		state      endpointHealthState
		correlated bool
	}
	now := time.Now()
	endpointHealth.Lock()
	items := make([]scored, 0, len(eps))
	for i, ep := range eps { items = append(items, scored{ep: ep, idx: i, state: endpointHealth.m[endpointKey(ep)]}) }
	endpointHealth.Unlock()

	// A healthy IP on the same provider / ASN is still useful, but after one
	// edge fails we prefer an independent failure domain first. Metadata is
	// optional, so configs without provider/ASN preserve ordinary health order.
	for i := range items {
		for j := range items {
			if i == j || !now.Before(items[j].state.CooldownUntil) { continue }
			sameProvider := items[i].ep.Provider != "" && items[i].ep.Provider == items[j].ep.Provider
			sameASN := items[i].ep.ASN != "" && items[i].ep.ASN == items[j].ep.ASN
			if sameProvider || sameASN { items[i].correlated = true; break }
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		aCool := now.Before(a.state.CooldownUntil)
		bCool := now.Before(b.state.CooldownUntil)
		if aCool != bCool { return !aCool }
		if a.correlated != b.correlated { return !a.correlated }
		if a.state.Failures != b.state.Failures { return a.state.Failures < b.state.Failures }
		if !a.state.LastSuccess.Equal(b.state.LastSuccess) {
			if a.state.LastSuccess.IsZero() { return false }
			if b.state.LastSuccess.IsZero() { return true }
			return a.state.LastSuccess.After(b.state.LastSuccess)
		}
		return a.idx < b.idx
	})
	out := make([]config.EndpointConfig, len(items))
	for i := range items { out[i] = items[i].ep }
	return out
}

func endpointHealthSnapshot() map[string]endpointHealthState {
	endpointHealth.Lock()
	defer endpointHealth.Unlock()
	out := make(map[string]endpointHealthState, len(endpointHealth.m))
	for k, v := range endpointHealth.m { out[k] = v }
	return out
}
