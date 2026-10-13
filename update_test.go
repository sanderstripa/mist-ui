package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func packageBytes(entries map[string]string) []byte {
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for name, value := range entries {
		tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(value)), Typeflag: tar.TypeReg})
		tw.Write([]byte(value))
	}
	tw.Close()
	gz.Close()
	return b.Bytes()
}
func TestUpdaterPackageBoundaries(t *testing.T) {
	if !newer("v0.2.0", "0.1.3") || newer("v0.1.2", "0.2.0") || newer("v0.2.0", "0.2.0") {
		t.Fatal("version ordering")
	}
	if safeReleaseURL("https://evil.example/mist-ui/releases/download/v1.0.0/a", "v1.0.0") {
		t.Fatal("external release accepted")
	}
	dir := t.TempDir()
	if err := unpackPair(packageBytes(map[string]string{"mist-ui": "panel", "mist-edge": "core", "../escape": "bad"}), dir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "escape")); err == nil {
		t.Fatal("archive traversal")
	}
	if err := unpackPair(packageBytes(map[string]string{"mist-ui": "panel"}), t.TempDir()); err == nil {
		t.Fatal("incomplete package accepted")
	}
}
func TestUsageAcrossCoreRestarts(t *testing.T) {
	a := testApp(t)
	ip := "10.77.43.2"
	first := a.accountTraffic(map[string]Traffic{ip: {RX: 100, TX: 300, Epoch: 1, LastSeen: 10}})
	second := a.accountTraffic(map[string]Traffic{ip: {RX: 100, TX: 300, Epoch: 1}})
	if first[ip].RX != second[ip].RX {
		t.Fatal("double counting")
	}
	third := a.accountTraffic(map[string]Traffic{ip: {RX: 150, TX: 400, Epoch: 2, LastSeen: 20}})
	if third[ip].RX != 250 || third[ip].TX != 700 || third[ip].LastSeen != 20 {
		t.Fatal(third)
	}
	none := a.accountTraffic(map[string]Traffic{})
	if none[ip].RX != 250 || none[ip].Active {
		t.Fatal("lost history")
	}
}
func TestEditDeleteAndReservedAddress(t *testing.T) {
	a := testApp(t)
	server := httptest.NewTLSServer(a.routes())
	defer server.Close()
	s := apiTest{t: t, server: server}
	s.login()
	code, _ := s.request("keys", "POST", `{"name":"A","days":0}`)
	if code != 201 {
		t.Fatal(code)
	}
	id := a.state.Keys[0].ID
	address := a.state.Keys[0].Address
	if code, _ = s.request("keys/"+id+"/edit", "POST", `{"name":"Renamed","days":30}`); code != 200 || a.state.Keys[0].Name != "Renamed" || a.state.Keys[0].Expires == 0 {
		t.Fatal("edit")
	}
	if code, _ = s.request("keys/"+id+"/delete", "POST", `{}`); code != 200 || !a.state.Keys[0].Deleted || !a.state.Keys[0].Revoked || a.state.Keys[0].Enabled {
		t.Fatal("delete did not revoke")
	}
	s.request("keys", "POST", `{"name":"B","days":0}`)
	if a.state.Keys[1].Address == address {
		t.Fatal("deleted address reused")
	}
	_, raw := s.request("state", "GET", "")
	if bytes.Contains(raw, []byte(id)) {
		t.Fatal("deleted key visible")
	}
}
