package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/config"
)

// Endpoint discovery deliberately uses a signed opaque payload instead of
// signing re-serialized JSON. That keeps verification deterministic across
// encoders and lets the HTTPS origin be mirrored by untrusted infrastructure.
type discoveryEnvelope struct {
	PayloadBase64   string `json:"payload_base64"`
	SignatureBase64 string `json:"signature_base64"`
}

type discoveryPayload struct {
	Version     int                     `json:"version"`
	ExpiresUnix int64                   `json:"expires_unix"`
	Endpoints   []config.EndpointConfig `json:"endpoints"`
}

var discoveryState struct {
	sync.Mutex
	loaded bool
	endpoints []config.EndpointConfig
	err error
}

func resolvedEndpointCandidates(ctx context.Context, cfg config.ClientConfig) ([]config.EndpointConfig, error) {
	static := cfg.EndpointCandidates()
	if cfg.EndpointDiscoveryURL == "" { return static, nil }

	discoveryState.Lock()
	if discoveryState.loaded {
		discovered, err := append([]config.EndpointConfig(nil), discoveryState.endpoints...), discoveryState.err
		discoveryState.Unlock()
		if len(static) > 0 { return mergeEndpoints(static, discovered), nil }
		return discovered, err
	}
	discoveryState.Unlock()

	discovered, err := fetchEndpointManifest(ctx, cfg)
	discoveryState.Lock()
	if !discoveryState.loaded {
		discoveryState.loaded = true
		discoveryState.endpoints = append([]config.EndpointConfig(nil), discovered...)
		discoveryState.err = err
	}
	discovered, err = append([]config.EndpointConfig(nil), discoveryState.endpoints...), discoveryState.err
	discoveryState.Unlock()

	if err != nil && len(static) == 0 { return nil, err }
	return mergeEndpoints(static, discovered), nil
}

func fetchEndpointManifest(parent context.Context, cfg config.ClientConfig) ([]config.EndpointConfig, error) {
	ctx, cancel := context.WithTimeout(parent, time.Duration(cfg.EndpointDiscoveryTimeoutSeconds)*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cfg.EndpointDiscoveryURL, nil)
	if err != nil { return nil, err }
	req.Header.Set("Accept", "application/json")
	rsp, err := http.DefaultClient.Do(req)
	if err != nil { return nil, fmt.Errorf("endpoint discovery: %w", err) }
	defer rsp.Body.Close()
	if rsp.StatusCode != http.StatusOK { return nil, fmt.Errorf("endpoint discovery: HTTP %s", rsp.Status) }
	body, err := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
	if err != nil { return nil, err }
	var env discoveryEnvelope
	dec := json.NewDecoder(strings.NewReader(string(body))); dec.DisallowUnknownFields()
	if err := dec.Decode(&env); err != nil { return nil, fmt.Errorf("endpoint discovery envelope: %w", err) }
	payloadBytes, err := base64.StdEncoding.DecodeString(env.PayloadBase64)
	if err != nil { return nil, fmt.Errorf("endpoint discovery payload: %w", err) }
	sig, err := base64.StdEncoding.DecodeString(env.SignatureBase64)
	if err != nil { return nil, fmt.Errorf("endpoint discovery signature: %w", err) }
	pub, _ := base64.StdEncoding.DecodeString(cfg.EndpointDiscoveryPublicKeyBase64)
	if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(pub), payloadBytes, sig) {
		return nil, errors.New("endpoint discovery signature verification failed")
	}
	var payload discoveryPayload
	pdec := json.NewDecoder(strings.NewReader(string(payloadBytes))); pdec.DisallowUnknownFields()
	if err := pdec.Decode(&payload); err != nil { return nil, fmt.Errorf("endpoint discovery payload JSON: %w", err) }
	if payload.Version != 1 { return nil, fmt.Errorf("unsupported endpoint discovery version %d", payload.Version) }
	if payload.ExpiresUnix <= time.Now().Unix() { return nil, errors.New("endpoint discovery manifest expired") }
	if payload.ExpiresUnix > time.Now().Add(7*24*time.Hour).Unix() { return nil, errors.New("endpoint discovery manifest expiry is unreasonably far in the future") }
	if len(payload.Endpoints) == 0 || len(payload.Endpoints) > 64 { return nil, fmt.Errorf("endpoint discovery contains %d endpoints", len(payload.Endpoints)) }

	out := make([]config.EndpointConfig, 0, len(payload.Endpoints))
	for i, ep := range payload.Endpoints {
		for _, expanded := range expandEndpoint(ep) {
			if expanded.Authority == "" || expanded.Path == "" || !strings.HasPrefix(expanded.Path, "/") { return nil, fmt.Errorf("endpoint discovery endpoint %d is incomplete", i) }
			host, _, err := net.SplitHostPort(expanded.DialAddress)
			if err != nil { return nil, fmt.Errorf("endpoint discovery endpoint %d dial address: %w", i, err) }
			ip, err := netip.ParseAddr(host)
			if err != nil || !ip.Is4() { return nil, fmt.Errorf("endpoint discovery endpoint %d must use an IPv4 literal dial address", i) }
			out = append(out, expanded)
		}
	}
	return out, nil
}

func expandEndpoint(ep config.EndpointConfig) []config.EndpointConfig {
	if len(ep.DialAddresses) == 0 { return []config.EndpointConfig{ep} }
	out := make([]config.EndpointConfig, 0, len(ep.DialAddresses))
	for _, addr := range ep.DialAddresses {
		clone := ep
		clone.DialAddress = addr
		clone.DialAddresses = nil
		out = append(out, clone)
	}
	return out
}

func mergeEndpoints(groups ...[]config.EndpointConfig) []config.EndpointConfig {
	seen := make(map[string]struct{})
	out := make([]config.EndpointConfig, 0)
	for _, group := range groups {
		for _, ep := range group {
			k := endpointKey(ep)
			if _, ok := seen[k]; ok { continue }
			seen[k] = struct{}{}
			out = append(out, ep)
		}
	}
	return out
}
