package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(p, []byte(body), 0600); err != nil { t.Fatal(err) }
	return p
}

func TestClientHardeningDefaults(t *testing.T) {
	p := writeConfig(t, `{
		"endpoint":{"authority":"edge.example.com","dial_address":"203.0.113.10:443","path":"/x"},
		"token":"secret","dns":["1.1.1.1"],"h2_fallback":true
	}`)
	c, err := LoadClient(p)
	if err != nil { t.Fatal(err) }
	if c.MTU != 1280 || c.MSSClamp != 1200 { t.Fatalf("unexpected mtu/mss: %d/%d", c.MTU, c.MSSClamp) }
	if c.InnerQUICPolicy != "auto" || c.PMTUMode != "auto" || c.KillSwitch != "fail_closed" { t.Fatalf("unexpected defaults: %+v", c) }
	if len(c.EndpointCandidates()) != 1 { t.Fatal("expected one endpoint") }
	if c.EndpointDiscoveryTimeoutSeconds != 5 { t.Fatalf("discovery timeout=%d", c.EndpointDiscoveryTimeoutSeconds) }
}

func TestClientMultipleEndpoints(t *testing.T) {
	p := writeConfig(t, `{
		"endpoints":[
			{"authority":"a.example.com","dial_address":"203.0.113.10:443","path":"/x"},
			{"authority":"b.example.com","dial_address":"198.51.100.20:443","path":"/x"}
		],
		"token":"secret","inner_quic_policy":"allow","kill_switch":"fail_open"
	}`)
	c, err := LoadClient(p)
	if err != nil { t.Fatal(err) }
	if got := len(c.EndpointCandidates()); got != 2 { t.Fatalf("endpoints=%d", got) }
}

func TestClientExpandsDialAddresses(t *testing.T) {
	p := writeConfig(t, `{
		"endpoint":{"authority":"edge.example.com","dial_addresses":["203.0.113.10:443","203.0.113.10:8443"],"path":"/x","provider":"alpha","asn":"AS64500"},
		"token":"secret"
	}`)
	c, err := LoadClient(p)
	if err != nil { t.Fatal(err) }
	eps := c.EndpointCandidates()
	if len(eps) != 2 { t.Fatalf("endpoints=%d", len(eps)) }
	if eps[0].DialAddress != "203.0.113.10:443" || eps[1].DialAddress != "203.0.113.10:8443" { t.Fatalf("unexpected expansion: %+v", eps) }
	if eps[1].Provider != "alpha" || eps[1].ASN != "AS64500" { t.Fatalf("metadata lost: %+v", eps[1]) }
}

func TestClientValidatesSignedDiscoveryConfig(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	key := base64.StdEncoding.EncodeToString(pub)
	p := writeConfig(t, `{"token":"secret","endpoint_discovery_url":"https://bootstrap.example.com/mist.json","endpoint_discovery_public_key_base64":"`+key+`"}`)
	c, err := LoadClient(p)
	if err != nil { t.Fatal(err) }
	if c.EndpointDiscoveryURL == "" { t.Fatal("discovery URL missing") }
	bad := writeConfig(t, `{"token":"secret","endpoint_discovery_url":"http://bootstrap.example.com/mist.json","endpoint_discovery_public_key_base64":"`+key+`"}`)
	if _, err := LoadClient(bad); err == nil { t.Fatal("insecure discovery URL accepted") }
}

func TestClientRealityFallbackRequiresH2(t *testing.T) {
	base := `"endpoint":{"authority":"edge.example.com","dial_address":"203.0.113.10:443","path":"/x"},"token":"secret"`
	badNoH2 := writeConfig(t, `{`+base+`,"reality_fallback_socks5":"127.0.0.1:1080"}`)
	if _, err := LoadClient(badNoH2); err == nil { t.Fatal("Reality fallback accepted without h2_fallback") }
	badAddr := writeConfig(t, `{`+base+`,"h2_fallback":true,"reality_fallback_socks5":"not-an-address"}`)
	if _, err := LoadClient(badAddr); err == nil { t.Fatal("invalid Reality SOCKS5 address accepted") }
	good := writeConfig(t, `{`+base+`,"h2_fallback":true,"reality_fallback_socks5":"127.0.0.1:1080"}`)
	c, err := LoadClient(good)
	if err != nil { t.Fatal(err) }
	if c.RealityFallbackSOCKS5 != "127.0.0.1:1080" { t.Fatalf("Reality SOCKS5 not preserved: %q", c.RealityFallbackSOCKS5) }
}

func TestRejectsUnsafeMTUAndModes(t *testing.T) {
	for _, body := range []string{
		`{"endpoint":{"authority":"e","dial_address":"203.0.113.1:443","path":"/x"},"token":"x","mtu":1600}`,
		`{"endpoint":{"authority":"e","dial_address":"203.0.113.1:443","path":"/x"},"token":"x","inner_quic_policy":"maybe"}`,
		`{"endpoint":{"authority":"e","dial_address":"203.0.113.1:443","path":"/x"},"token":"x","kill_switch":"maybe"}`,
	} {
		if _, err := LoadClient(writeConfig(t, body)); err == nil { t.Fatalf("config unexpectedly accepted: %s", body) }
	}
}

func TestServerAcceptsTokenSecret(t *testing.T) {
	p := writeConfig(t, `{
		"authority":"edge.example.com","path":"/x","certificate":"cert.pem","private_key":"key.pem",
		"token_secret":"0123456789abcdef0123456789abcdef",
		"tun_cidr":"10.64.0.1/24","client_cidr":"10.64.0.2/32",
		"port_hop_ports":[8443,9443]
	}`)
	c, err := LoadServer(p)
	if err != nil { t.Fatal(err) }
	if c.MTU != 1280 || c.AuthRateLimitPerMinute != 30 { t.Fatalf("unexpected server defaults: %+v", c) }
	if len(c.PortHopPorts) != 2 { t.Fatalf("port hops=%v", c.PortHopPorts) }
}

func TestServerAcceptsLegacyUnknownFields(t *testing.T) {
	p := writeConfig(t, `{
		"authority":"edge.example.com","path":"/x","certificate":"cert.pem","private_key":"key.pem","token":"x",
		"tun_cidr":"10.64.0.1/24","client_cidr":"10.64.0.2/32",
		"max_download_mbps":1000,"max_upload_mbps":1000,"legacy_transport_buffer":4194304
	}`)
	c, err := LoadServer(p)
	if err != nil { t.Fatal(err) }
	if c.Authority != "edge.example.com" || c.MTU != 1280 { t.Fatalf("legacy config did not load correctly: %+v", c) }
}

func TestServerMigratesMistFast2LegacyConfig(t *testing.T) {
	p := writeConfig(t, `{
		"listen":":443",
		"authority":"mist.sanderstripa.com",
		"path":"/mist-fast",
		"certificate":"/etc/letsencrypt/live/mist.sanderstripa.com/fullchain.pem",
		"private_key":"/etc/letsencrypt/live/mist.sanderstripa.com/privkey.pem",
		"token":"secret",
		"max_download_mbps":800,
		"max_upload_mbps":400,
		"transport":"h3-l4",
		"congestion":"brutal"
	}`)
	c, err := LoadServer(p)
	if err != nil { t.Fatal(err) }
	if c.TUNCIDR != "10.66.0.1/30" { t.Fatalf("tun_cidr=%q", c.TUNCIDR) }
	if c.ClientCIDR != "10.66.0.2/32" { t.Fatalf("client_cidr=%q", c.ClientCIDR) }
	if !c.EnableNAT { t.Fatal("legacy config should default enable_nat=true") }
	if c.AdvertiseCIDR != "0.0.0.0/0" || c.MTU != 1280 { t.Fatalf("unexpected legacy defaults: %+v", c) }
}

func TestServerRejectsDuplicatePortHop(t *testing.T) {
	p := writeConfig(t, `{
		"authority":"edge.example.com","path":"/x","certificate":"cert.pem","private_key":"key.pem","token":"x",
		"tun_cidr":"10.64.0.1/24","client_cidr":"10.64.0.2/32","port_hop_ports":[8443,8443]
	}`)
	if _, err := LoadServer(p); err == nil { t.Fatal("duplicate port hop accepted") }
}
