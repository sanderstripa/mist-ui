package config

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"
)

type ClientConfig struct {
	Endpoint  EndpointConfig   `json:"endpoint"`
	Endpoints []EndpointConfig `json:"endpoints,omitempty"`
	Token     string           `json:"token"`
	TUNName   string           `json:"tun_name"`
	MTU       int              `json:"mtu"`
	DNS       []string         `json:"dns"`

	H2Fallback         bool   `json:"h2_fallback,omitempty"`
	FallbackClientCIDR string `json:"fallback_client_cidr,omitempty"`

	InnerQUICPolicy          string `json:"inner_quic_policy,omitempty"`
	MSSClamp                 int    `json:"mss_clamp,omitempty"`
	PMTUMode                 string `json:"pmtu_mode,omitempty"`
	KillSwitch               string `json:"kill_switch,omitempty"`
	TelemetryIntervalSeconds int    `json:"telemetry_interval_seconds,omitempty"`
	WireProfile              string `json:"wire_profile,omitempty"`
	EndpointStrategy         string `json:"endpoint_strategy,omitempty"`
	IPv6Mode                 string `json:"ipv6_mode,omitempty"`
	FallbackClientIPv6CIDR   string `json:"fallback_client_ipv6_cidr,omitempty"`

	EndpointDiscoveryURL             string `json:"endpoint_discovery_url,omitempty"`
	EndpointDiscoveryPublicKeyBase64 string `json:"endpoint_discovery_public_key_base64,omitempty"`
	EndpointDiscoveryTimeoutSeconds  int    `json:"endpoint_discovery_timeout_seconds,omitempty"`

	RealityFallbackSOCKS5 string `json:"reality_fallback_socks5,omitempty"`
}

type EndpointConfig struct {
	Authority       string   `json:"authority"`
	DialAddress     string   `json:"dial_address,omitempty"`
	DialAddresses   []string `json:"dial_addresses,omitempty"`
	Path            string   `json:"path"`
	ECHConfigBase64 string   `json:"ech_config_base64,omitempty"`
	Provider        string   `json:"provider,omitempty"`
	ASN             string   `json:"asn,omitempty"`
}

type ECHServerKeyConfig struct {
	ConfigBase64     string `json:"config_base64"`
	PrivateKeyBase64 string `json:"private_key_base64"`
	SendAsRetry      bool   `json:"send_as_retry"`
}

type ServerConfig struct {
	AccessPolicyFile string               `json:"access_policy_file,omitempty"`
	StatsFile        string               `json:"stats_file,omitempty"`
	Listen           string               `json:"listen"`
	Authority        string               `json:"authority"`
	Path             string               `json:"path"`
	Certificate      string               `json:"certificate"`
	PrivateKey       string               `json:"private_key"`
	Token            string               `json:"token"`
	TokenSecret      string               `json:"token_secret,omitempty"`
	TUNName          string               `json:"tun_name"`
	TUNCIDR          string               `json:"tun_cidr"`
	ClientCIDR       string               `json:"client_cidr"`
	AdvertiseCIDR    string               `json:"advertise_cidr"`
	MTU              int                  `json:"mtu"`
	EnableNAT        bool                 `json:"enable_nat"`
	ECHKeys          []ECHServerKeyConfig `json:"ech_keys,omitempty"`

	DecoyRoot                   string `json:"decoy_root,omitempty"`
	AuthRateLimitPerMinute      int    `json:"auth_rate_limit_per_minute,omitempty"`
	QUICRetryThresholdPerMinute int    `json:"quic_retry_threshold_per_minute,omitempty"`
	MaxIncomingStreams          int64  `json:"max_incoming_streams,omitempty"`
	WireProfile                 string `json:"wire_profile,omitempty"`

	TUNIPv6CIDR       string `json:"tun_ipv6_cidr,omitempty"`
	ClientIPv6CIDR    string `json:"client_ipv6_cidr,omitempty"`
	AdvertiseIPv6CIDR string `json:"advertise_ipv6_cidr,omitempty"`

	PortHopPorts []int `json:"port_hop_ports,omitempty"`
}

func LoadClient(path string) (ClientConfig, error) {
	var cfg ClientConfig
	if err := load(path, &cfg); err != nil {
		return cfg, err
	}
	if cfg.TUNName == "" {
		cfg.TUNName = "MIST"
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if cfg.MTU < 1200 || cfg.MTU > 1500 {
		return cfg, fmt.Errorf("mtu must be between 1200 and 1500, got %d", cfg.MTU)
	}
	if cfg.FallbackClientCIDR == "" {
		cfg.FallbackClientCIDR = "10.64.0.2/32"
	}
	if cfg.H2Fallback {
		p, err := netip.ParsePrefix(cfg.FallbackClientCIDR)
		if err != nil || !p.Addr().Is4() {
			return cfg, fmt.Errorf("invalid fallback_client_cidr: %q", cfg.FallbackClientCIDR)
		}
	}
	if cfg.Token == "" {
		return cfg, errors.New("token is required")
	}

	if cfg.InnerQUICPolicy == "" {
		cfg.InnerQUICPolicy = "auto"
	}
	switch cfg.InnerQUICPolicy {
	case "auto", "block", "allow":
	default:
		return cfg, fmt.Errorf("inner_quic_policy must be auto, block, or allow; got %q", cfg.InnerQUICPolicy)
	}
	if cfg.MSSClamp == 0 {
		cfg.MSSClamp = min(1200, cfg.MTU-60)
	}
	if cfg.MSSClamp < 536 || cfg.MSSClamp > cfg.MTU-40 {
		return cfg, fmt.Errorf("mss_clamp must be between 536 and mtu-40; got %d", cfg.MSSClamp)
	}
	if cfg.PMTUMode == "" {
		cfg.PMTUMode = "auto"
	}
	if cfg.PMTUMode != "auto" && cfg.PMTUMode != "off" {
		return cfg, fmt.Errorf("pmtu_mode must be auto or off; got %q", cfg.PMTUMode)
	}
	if cfg.KillSwitch == "" {
		cfg.KillSwitch = "fail_closed"
	}
	if cfg.KillSwitch != "fail_closed" && cfg.KillSwitch != "fail_open" {
		return cfg, fmt.Errorf("kill_switch must be fail_closed or fail_open; got %q", cfg.KillSwitch)
	}
	if cfg.TelemetryIntervalSeconds == 0 {
		cfg.TelemetryIntervalSeconds = 10
	}
	if cfg.TelemetryIntervalSeconds < 1 || cfg.TelemetryIntervalSeconds > 3600 {
		return cfg, errors.New("telemetry_interval_seconds must be between 1 and 3600")
	}
	if cfg.WireProfile == "" {
		cfg.WireProfile = "native"
	}
	if cfg.WireProfile != "native" {
		return cfg, fmt.Errorf("wire_profile %q is not supported; use native", cfg.WireProfile)
	}
	if cfg.EndpointStrategy == "" {
		cfg.EndpointStrategy = "ordered"
	}
	if cfg.EndpointStrategy != "ordered" {
		return cfg, fmt.Errorf("endpoint_strategy %q is not supported; use ordered", cfg.EndpointStrategy)
	}
	if cfg.IPv6Mode == "" {
		cfg.IPv6Mode = "block"
	}
	if cfg.IPv6Mode != "block" && cfg.IPv6Mode != "tunnel" {
		return cfg, fmt.Errorf("ipv6_mode must be block or tunnel; got %q", cfg.IPv6Mode)
	}
	if cfg.IPv6Mode == "tunnel" {
		p, err := netip.ParsePrefix(cfg.FallbackClientIPv6CIDR)
		if err != nil || !p.Addr().Is6() {
			return cfg, fmt.Errorf("fallback_client_ipv6_cidr is required for ipv6_mode=tunnel")
		}
	}

	if cfg.EndpointDiscoveryURL != "" || cfg.EndpointDiscoveryPublicKeyBase64 != "" {
		if cfg.EndpointDiscoveryURL == "" || cfg.EndpointDiscoveryPublicKeyBase64 == "" {
			return cfg, errors.New("endpoint discovery URL and public key must be configured together")
		}
		u, err := url.Parse(cfg.EndpointDiscoveryURL)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return cfg, errors.New("endpoint_discovery_url must be an absolute HTTPS URL")
		}
		key, err := base64.StdEncoding.DecodeString(cfg.EndpointDiscoveryPublicKeyBase64)
		if err != nil || len(key) != 32 {
			return cfg, errors.New("endpoint_discovery_public_key_base64 must encode a 32-byte Ed25519 public key")
		}
	}
	if cfg.EndpointDiscoveryTimeoutSeconds == 0 {
		cfg.EndpointDiscoveryTimeoutSeconds = 5
	}
	if cfg.EndpointDiscoveryTimeoutSeconds < 1 || cfg.EndpointDiscoveryTimeoutSeconds > 30 {
		return cfg, errors.New("endpoint_discovery_timeout_seconds must be between 1 and 30")
	}
	if cfg.RealityFallbackSOCKS5 != "" {
		if _, _, err := net.SplitHostPort(cfg.RealityFallbackSOCKS5); err != nil {
			return cfg, fmt.Errorf("invalid reality_fallback_socks5: %w", err)
		}
		if !cfg.H2Fallback {
			return cfg, errors.New("reality_fallback_socks5 requires h2_fallback=true")
		}
	}

	eps := cfg.EndpointCandidates()
	for i, ep := range eps {
		if err := validateEndpoint(ep); err != nil {
			return cfg, fmt.Errorf("endpoint %d: %w", i, err)
		}
	}
	if len(eps) == 0 && cfg.EndpointDiscoveryURL == "" {
		return cfg, errors.New("at least one endpoint or endpoint discovery URL is required")
	}
	return cfg, nil
}

func (c ClientConfig) EndpointCandidates() []EndpointConfig {
	src := c.Endpoints
	if len(src) == 0 && (c.Endpoint.Authority != "" || c.Endpoint.DialAddress != "" || len(c.Endpoint.DialAddresses) > 0 || c.Endpoint.Path != "") {
		src = []EndpointConfig{c.Endpoint}
	}
	out := make([]EndpointConfig, 0, len(src))
	for _, ep := range src {
		if len(ep.DialAddresses) == 0 {
			out = append(out, ep)
			continue
		}
		for _, addr := range ep.DialAddresses {
			clone := ep
			clone.DialAddress = addr
			clone.DialAddresses = nil
			out = append(out, clone)
		}
	}
	return out
}

func validateEndpoint(ep EndpointConfig) error {
	if ep.Path == "" {
		return errors.New("path is required")
	}
	if !strings.HasPrefix(ep.Path, "/") {
		return errors.New("path must start with /")
	}
	if ep.Authority == "" {
		return errors.New("authority is required")
	}
	if ep.DialAddress == "" {
		return errors.New("dial_address is required after expansion")
	}
	host, _, err := net.SplitHostPort(ep.DialAddress)
	if err != nil {
		return fmt.Errorf("invalid dial_address: %w", err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is4() {
		return fmt.Errorf("dial_address must use an IPv4 literal so MIST can pin the Edge outside the fail-closed tunnel, got %q", host)
	}
	return nil
}

func LoadServer(path string) (ServerConfig, error) {
	var cfg ServerConfig
	raw, err := loadServer(path, &cfg)
	if err != nil {
		return cfg, err
	}

	legacy := false
	if cfg.Listen == "" {
		cfg.Listen = rawString(raw, "bind", "listen_addr")
	}
	if cfg.Listen == "" {
		cfg.Listen = ":443"
	}
	if cfg.Authority == "" {
		cfg.Authority = rawString(raw, "server_name", "domain", "host")
	}
	if cfg.Path == "" {
		cfg.Path = rawString(raw, "endpoint_path", "uri")
	}
	if cfg.Certificate == "" {
		cfg.Certificate = rawString(raw, "cert", "cert_file", "tls_cert", "cert_path")
	}
	if cfg.PrivateKey == "" {
		cfg.PrivateKey = rawString(raw, "key", "key_file", "tls_key", "key_path")
	}
	if cfg.Token == "" {
		cfg.Token = rawString(raw, "auth_token", "psk", "secret")
	}
	if cfg.TUNName == "" {
		cfg.TUNName = rawString(raw, "interface", "tun_interface")
	}
	if cfg.TUNName == "" {
		cfg.TUNName = "mist0"
	}
	if cfg.TUNCIDR == "" {
		cfg.TUNCIDR = rawString(raw, "server_tun_cidr", "tun_address", "tun_addr")
	}
	if cfg.TUNCIDR == "" {
		cfg.TUNCIDR = "10.66.0.1/30"
		legacy = true
	}
	if cfg.ClientCIDR == "" {
		cfg.ClientCIDR = rawString(raw, "client_tun_cidr", "client_address", "client_addr")
	}
	if cfg.ClientCIDR == "" {
		cfg.ClientCIDR = "10.66.0.2/32"
		legacy = true
	}
	if cfg.AdvertiseCIDR == "" {
		cfg.AdvertiseCIDR = rawString(raw, "route_cidr", "advertise_route")
	}
	if cfg.AdvertiseCIDR == "" {
		cfg.AdvertiseCIDR = "0.0.0.0/0"
	}
	if cfg.MTU == 0 {
		cfg.MTU = rawInt(raw, "tun_mtu")
	}
	if cfg.MTU == 0 {
		cfg.MTU = 1280
	}
	if legacy && !rawHas(raw, "enable_nat") {
		cfg.EnableNAT = true
	}
	if cfg.AuthRateLimitPerMinute == 0 {
		cfg.AuthRateLimitPerMinute = 30
	}
	if cfg.QUICRetryThresholdPerMinute == 0 {
		cfg.QUICRetryThresholdPerMinute = 60
	}
	if cfg.MaxIncomingStreams == 0 {
		cfg.MaxIncomingStreams = 32
	}
	if cfg.WireProfile == "" {
		cfg.WireProfile = "native"
	}

	for field, value := range map[string]string{"authority": cfg.Authority, "path": cfg.Path, "certificate": cfg.Certificate, "private_key": cfg.PrivateKey, "tun_cidr": cfg.TUNCIDR, "client_cidr": cfg.ClientCIDR} {
		if value == "" {
			return cfg, fmt.Errorf("%s is required", field)
		}
	}
	if cfg.Token == "" && cfg.TokenSecret == "" && cfg.AccessPolicyFile == "" {
		return cfg, errors.New("token, token_secret or access_policy_file is required")
	}
	if !strings.HasPrefix(cfg.Path, "/") {
		return cfg, errors.New("path must start with /")
	}
	if cfg.AuthRateLimitPerMinute < 1 || cfg.AuthRateLimitPerMinute > 100000 {
		return cfg, errors.New("auth_rate_limit_per_minute must be between 1 and 100000")
	}
	if cfg.QUICRetryThresholdPerMinute < 1 || cfg.QUICRetryThresholdPerMinute > 100000 {
		return cfg, errors.New("quic_retry_threshold_per_minute must be between 1 and 100000")
	}
	if cfg.MaxIncomingStreams < 8 || cfg.MaxIncomingStreams > 10000 {
		return cfg, errors.New("max_incoming_streams must be between 8 and 10000")
	}
	if cfg.WireProfile != "native" {
		return cfg, fmt.Errorf("wire_profile %q is not supported; use native", cfg.WireProfile)
	}
	if _, port, err := net.SplitHostPort(cfg.Listen); err != nil || port == "" {
		return cfg, fmt.Errorf("listen must include a port: %q", cfg.Listen)
	}
	seenPorts := map[int]struct{}{}
	for _, port := range cfg.PortHopPorts {
		if port < 1 || port > 65535 {
			return cfg, fmt.Errorf("port_hop_ports contains invalid port %d", port)
		}
		if _, ok := seenPorts[port]; ok {
			return cfg, fmt.Errorf("port_hop_ports contains duplicate port %d", port)
		}
		seenPorts[port] = struct{}{}
	}
	if cfg.TUNIPv6CIDR != "" || cfg.ClientIPv6CIDR != "" || cfg.AdvertiseIPv6CIDR != "" {
		for name, value := range map[string]string{"tun_ipv6_cidr": cfg.TUNIPv6CIDR, "client_ipv6_cidr": cfg.ClientIPv6CIDR, "advertise_ipv6_cidr": cfg.AdvertiseIPv6CIDR} {
			p, err := netip.ParsePrefix(value)
			if err != nil || !p.Addr().Is6() {
				return cfg, fmt.Errorf("%s must be a valid IPv6 prefix", name)
			}
		}
	}
	return cfg, nil
}

func load(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode %s: %w", path, err)
	}
	return nil
}

func loadServer(path string, dst any) (map[string]json.RawMessage, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	if err := json.Unmarshal(b, dst); err != nil {
		return nil, fmt.Errorf("decode %s: %w", path, err)
	}
	return raw, nil
}

func rawString(raw map[string]json.RawMessage, keys ...string) string {
	for _, key := range keys {
		b, ok := raw[key]
		if !ok {
			continue
		}
		var s string
		if err := json.Unmarshal(b, &s); err == nil && s != "" {
			return s
		}
	}
	return ""
}

func rawInt(raw map[string]json.RawMessage, keys ...string) int {
	for _, key := range keys {
		b, ok := raw[key]
		if !ok {
			continue
		}
		var n int
		if err := json.Unmarshal(b, &n); err == nil && n != 0 {
			return n
		}
	}
	return 0
}

func rawHas(raw map[string]json.RawMessage, key string) bool {
	_, ok := raw[key]
	return ok
}
