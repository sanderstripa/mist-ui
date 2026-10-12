package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"golang.org/x/crypto/bcrypt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func testApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	hash, _ := bcrypt.GenerateFromPassword([]byte("secure-test-password"), bcrypt.MinCost)
	cfg := Config{Username: "admin", PassHash: string(hash), WebPath: "/test-panel", ServerFile: filepath.Join(dir, "server.json"), StatsFile: filepath.Join(dir, "stats.json")}
	server := map[string]any{"authority": "192.0.2.1", "listen": ":443", "path": "/assets/test", "tun_cidr": "10.77.43.1/24", "mtu": 1280}
	if err := writeJSON(cfg.ServerFile, server); err != nil {
		t.Fatal(err)
	}
	a := &App{cfg: cfg, state: State{Version: 1, Name: "MIST", DNS: []string{"1.1.1.1"}, Keys: []Device{}}, dir: dir, sessions: map[string]Session{}, attempts: map[string][]time.Time{}, control: func(s string) (string, error) { return "active", nil }}
	_ = writeJSON(filepath.Join(dir, "config.json"), cfg)
	return a
}

type apiTest struct {
	t      *testing.T
	server *httptest.Server
	csrf   string
	cookie *http.Cookie
}

func (s *apiTest) request(path, method, raw string) (int, []byte) {
	s.t.Helper()
	req, _ := http.NewRequest(method, s.server.URL+"/test-panel/api/"+path, strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", s.csrf)
	if s.cookie != nil {
		req.AddCookie(s.cookie)
	}
	resp, err := s.server.Client().Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	defer resp.Body.Close()
	for _, c := range resp.Cookies() {
		s.cookie = c
	}
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}
func (s *apiTest) login() {
	s.t.Helper()
	code, b := s.request("login", "POST", `{"username":"admin","password":"secure-test-password"}`)
	if code != 200 {
		s.t.Fatalf("login %d %s", code, b)
	}
	var v map[string]string
	_ = json.Unmarshal(b, &v)
	s.csrf = v["csrf"]
	if !s.cookie.HttpOnly || !s.cookie.Secure || s.cookie.SameSite != http.SameSiteStrictMode {
		s.t.Fatal("unsafe cookie")
	}
}
func TestAuthKeysAndRevocation(t *testing.T) {
	a := testApp(t)
	server := httptest.NewTLSServer(a.routes())
	defer server.Close()
	s := apiTest{t: t, server: server}
	if code, _ := s.request("state", "GET", ""); code != 401 {
		t.Fatal("state accessible without auth")
	}
	s.login()
	csrf := s.csrf
	s.csrf = ""
	if code, _ := s.request("keys", "POST", `{"name":"Laptop","days":0}`); code != 403 {
		t.Fatal("CSRF missing")
	}
	s.csrf = csrf
	var ids []string
	for _, name := range []string{"Laptop", "Phone"} {
		code, b := s.request("keys", "POST", `{"name":"`+name+`","days":0}`)
		if code != 201 {
			t.Fatalf("create %d %s", code, b)
		}
		var v map[string]string
		_ = json.Unmarshal(b, &v)
		ids = append(ids, v["id"])
	}
	if a.state.Keys[0].Token == a.state.Keys[1].Token || a.state.Keys[0].Address == a.state.Keys[1].Address {
		t.Fatal("devices not independent")
	}
	code, b := s.request("keys/"+ids[0]+"/link", "GET", "")
	if code != 200 {
		t.Fatal("link failed")
	}
	var v map[string]string
	_ = json.Unmarshal(b, &v)
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(v["link"], "mist://"))
	if err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal(raw, &cfg)
	if cfg["fallback_client_cidr"] != a.state.Keys[0].Address+"/32" || cfg["token"] != a.state.Keys[0].Token {
		t.Fatal("link does not match allocated key")
	}
	if code, _ = s.request("keys/"+ids[0]+"/revoke", "POST", `{}`); code != 200 {
		t.Fatal("revoke failed")
	}
	if code, _ = s.request("keys/"+ids[0]+"/enable", "POST", `{}`); code != 409 {
		t.Fatal("revoked key resurrected")
	}
	if code, _ = s.request("keys/"+ids[0]+"/link", "GET", ""); code != 404 {
		t.Fatal("revoked key exported")
	}
	if code, _ = s.request("keys/"+ids[1]+"/link", "GET", ""); code != 200 {
		t.Fatal("revocation affected other device")
	}
	var saved State
	_ = readJSON(filepath.Join(a.dir, "state.json"), &saved)
	if !saved.Keys[0].Revoked || saved.Keys[0].Enabled {
		t.Fatal("revocation not persisted")
	}
	code, b = s.request("state", "GET", "")
	if code != 200 || bytes.Contains(b, []byte(a.state.Keys[1].Token)) {
		t.Fatal("state leaked token")
	}
	info, _ := os.Stat(filepath.Join(a.dir, "state.json"))
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatal("unsafe state permissions")
	}
}
func TestRateLimitAndPasswordSessions(t *testing.T) {
	a := testApp(t)
	server := httptest.NewTLSServer(a.routes())
	defer server.Close()
	s := apiTest{t: t, server: server}
	s.login()
	if code, _ := s.request("password", "POST", `{"current":"secure-test-password","new":"new-secure-password"}`); code != 200 {
		t.Fatal("password change failed")
	}
	if code, _ := s.request("state", "GET", ""); code != 401 {
		t.Fatal("old session survived password change")
	}
	for i := 0; i < 5; i++ {
		s.request("login", "POST", `{"username":"admin","password":"bad"}`)
	}
	if code, _ := s.request("login", "POST", `{"username":"admin","password":"bad"}`); code != 429 {
		t.Fatal("login rate limit missing")
	}
}
func TestInitializerAdoptsLegacyWithoutChangingLink(t *testing.T) {
	dir := t.TempDir()
	server := filepath.Join(dir, "server.json")
	cfg := Config{Username: "admin", Listen: ":2097", Cert: "cert.pem", TLSKey: "key.pem", ServerFile: server, StatsFile: filepath.Join(dir, "stats.json")}
	old := map[string]any{"token": "old-working-token", "authority": "192.0.2.1", "listen": ":443", "path": "/mist", "tun_cidr": "10.77.43.1/24", "client_cidr": "10.77.43.2/32"}
	_ = writeJSON(server, old)
	data := filepath.Join(dir, "panel")
	if err := initialize(data, cfg, "secure-test-password"); err != nil {
		t.Fatal(err)
	}
	a, err := loadApp(data)
	if err != nil {
		t.Fatal(err)
	}
	if a.state.Keys[0].Token != "old-working-token" || a.state.Keys[0].Address != "10.77.43.2" {
		t.Fatal("working legacy key changed")
	}
	var core map[string]any
	_ = readJSON(server, &core)
	if _, ok := core["token"]; ok {
		t.Fatal("legacy token bypass remains")
	}
	if core["access_policy_file"] != filepath.Join(data, "state.json") {
		t.Fatal("core policy not connected")
	}
	if err = initialize(data, cfg, "secure-test-password"); err == nil {
		t.Fatal("existing panel overwritten")
	}
}
func TestExpiryAndValidation(t *testing.T) {
	a := testApp(t)
	a.state.Keys = []Device{{ID: "expired", Token: "expired-token", Enabled: true, Address: "10.77.43.2", Expires: time.Now().Add(-time.Second).Unix()}}
	if _, err := a.clientLink("expired"); err == nil {
		t.Fatal("expired key export allowed")
	}
	s := httptest.NewTLSServer(a.routes())
	defer s.Close()
	client := apiTest{t: t, server: s}
	client.login()
	if code, _ := client.request("keys", "POST", `{"name":"a","days":-1}`); code != 400 {
		t.Fatal("invalid expiry accepted")
	}
	if code, _ := client.request("settings", "POST", `{"name":"x","dns":["not-an-ip"]}`); code != 400 {
		t.Fatal("invalid DNS accepted")
	}
}
