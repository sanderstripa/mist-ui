package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/sanderstripa/vpn/mist/internal/config"
)

func withDiscoveryServer(t *testing.T, env []byte, fn func(string)) {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(env) }))
	defer server.Close()
	old := http.DefaultClient
	http.DefaultClient = server.Client()
	defer func(){ http.DefaultClient = old }()
	fn(server.URL)
}

func TestFetchEndpointManifest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	payload, err := json.Marshal(discoveryPayload{
		Version: 1,
		ExpiresUnix: time.Now().Add(time.Hour).Unix(),
		Endpoints: []config.EndpointConfig{{Authority:"edge.example", DialAddresses:[]string{"203.0.113.1:443","203.0.113.1:8443"}, Path:"/x", Provider:"p", ASN:"AS64500"}},
	})
	if err != nil { t.Fatal(err) }
	sig := ed25519.Sign(priv, payload)
	env, _ := json.Marshal(discoveryEnvelope{PayloadBase64:base64.StdEncoding.EncodeToString(payload), SignatureBase64:base64.StdEncoding.EncodeToString(sig)})

	withDiscoveryServer(t, env, func(url string) {
		cfg := config.ClientConfig{EndpointDiscoveryURL:url, EndpointDiscoveryPublicKeyBase64:base64.StdEncoding.EncodeToString(pub), EndpointDiscoveryTimeoutSeconds:2}
		eps, err := fetchEndpointManifest(context.Background(), cfg)
		if err != nil { t.Fatal(err) }
		if len(eps) != 2 { t.Fatalf("endpoints=%d", len(eps)) }
		if eps[1].DialAddress != "203.0.113.1:8443" || eps[1].Provider != "p" { t.Fatalf("bad endpoint: %+v", eps[1]) }
	})
}

func TestFetchEndpointManifestRejectsSignature(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	payload := []byte(`{"version":1,"expires_unix":9999999999,"endpoints":[{"authority":"e","dial_address":"203.0.113.1:443","path":"/x"}]}`)
	env, _ := json.Marshal(discoveryEnvelope{PayloadBase64:base64.StdEncoding.EncodeToString(payload), SignatureBase64:base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))})
	withDiscoveryServer(t, env, func(url string) {
		cfg := config.ClientConfig{EndpointDiscoveryURL:url, EndpointDiscoveryPublicKeyBase64:base64.StdEncoding.EncodeToString(pub), EndpointDiscoveryTimeoutSeconds:2}
		if _, err := fetchEndpointManifest(context.Background(), cfg); err == nil { t.Fatal("bad signature accepted") }
	})
}

func TestFetchEndpointManifestRejectsExpiredPayload(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	payload, err := json.Marshal(discoveryPayload{
		Version: 1,
		ExpiresUnix: time.Now().Add(-time.Minute).Unix(),
		Endpoints: []config.EndpointConfig{{Authority:"edge.example", DialAddress:"203.0.113.1:443", Path:"/x"}},
	})
	if err != nil { t.Fatal(err) }
	env, _ := json.Marshal(discoveryEnvelope{
		PayloadBase64: base64.StdEncoding.EncodeToString(payload),
		SignatureBase64: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, payload)),
	})
	withDiscoveryServer(t, env, func(url string) {
		cfg := config.ClientConfig{EndpointDiscoveryURL:url, EndpointDiscoveryPublicKeyBase64:base64.StdEncoding.EncodeToString(pub), EndpointDiscoveryTimeoutSeconds:2}
		if _, err := fetchEndpointManifest(context.Background(), cfg); err == nil { t.Fatal("expired discovery manifest accepted") }
	})
}
