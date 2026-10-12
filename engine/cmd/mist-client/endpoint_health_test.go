package main

import (
	"testing"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/config"
)

func resetEndpointHealthForTest() {
	endpointHealth.Lock()
	endpointHealth.m = map[string]endpointHealthState{}
	endpointHealth.Unlock()
}

func TestOrderedEndpointsPrefersHealthyCandidate(t *testing.T) {
	a := config.EndpointConfig{Authority:"a.example", DialAddress:"203.0.113.1:443", Path:"/x"}
	b := config.EndpointConfig{Authority:"b.example", DialAddress:"198.51.100.1:443", Path:"/x"}
	resetEndpointHealthForTest()
	recordEndpointFailure(a, 2*time.Second)
	got := orderedEndpoints([]config.EndpointConfig{a,b})
	if len(got) != 2 || got[0].DialAddress != b.DialAddress { t.Fatalf("expected healthy endpoint first, got %+v", got) }
}

func TestEndpointSuccessClearsCooldown(t *testing.T) {
	a := config.EndpointConfig{Authority:"a.example", DialAddress:"203.0.113.1:443", Path:"/x"}
	resetEndpointHealthForTest()
	recordEndpointFailure(a, time.Second)
	recordEndpointSuccess(a, 10*time.Millisecond)
	s := endpointHealthSnapshot()[endpointKey(a)]
	if s.Failures != 0 || !s.CooldownUntil.IsZero() || s.Successes != 1 { t.Fatalf("unexpected state: %+v", s) }
}

func TestOrderedEndpointsPrefersIndependentFailureDomain(t *testing.T) {
	failed := config.EndpointConfig{Authority:"a1.example", DialAddress:"203.0.113.1:443", Path:"/x", Provider:"provider-a", ASN:"AS64500"}
	sameProvider := config.EndpointConfig{Authority:"a2.example", DialAddress:"203.0.113.2:443", Path:"/x", Provider:"provider-a", ASN:"AS64500"}
	independent := config.EndpointConfig{Authority:"b.example", DialAddress:"198.51.100.1:443", Path:"/x", Provider:"provider-b", ASN:"AS64501"}
	resetEndpointHealthForTest()
	recordEndpointFailure(failed, time.Second)
	got := orderedEndpoints([]config.EndpointConfig{failed, sameProvider, independent})
	if len(got) != 3 { t.Fatalf("unexpected endpoint count: %d", len(got)) }
	if got[0].DialAddress != independent.DialAddress { t.Fatalf("expected independent provider/ASN first, got %+v", got) }
	if got[1].DialAddress != sameProvider.DialAddress { t.Fatalf("expected correlated healthy endpoint second, got %+v", got) }
	if got[2].DialAddress != failed.DialAddress { t.Fatalf("expected cooled-down failed endpoint last, got %+v", got) }
}
