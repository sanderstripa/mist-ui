package main

import "github.com/sanderstripa/vpn/mist/internal/config"

// knownEndpointCandidates returns static endpoints plus the already verified
// startup manifest. It intentionally never performs network I/O: by the time
// the TUN routes are installed, all discovered endpoint IPs must already be
// known so they can be pinned outside the tunnel for fail-closed reconnects.
func knownEndpointCandidates(cfg config.ClientConfig) []config.EndpointConfig {
	static := cfg.EndpointCandidates()
	discoveryState.Lock()
	discovered := append([]config.EndpointConfig(nil), discoveryState.endpoints...)
	discoveryState.Unlock()
	return mergeEndpoints(static, discovered)
}
