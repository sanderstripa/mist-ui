package accesspolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLiveRevocationExpiryAndFailClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	s := Store{Path: path}
	write := func(p Policy) {
		b, _ := json.Marshal(p)
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, b, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Fatal(err)
		}
	}
	p := Policy{Version: 1, Keys: []Key{{ID: "device", TokenHash: Hash("valid-token"), Address: "10.77.43.2", Enabled: true}}}
	write(p)
	if _, err := s.Lookup("valid-token", time.Now()); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup("forged", time.Now()); err == nil {
		t.Fatal("forged token accepted")
	}
	p.Keys[0].Enabled = false
	write(p)
	if _, err := s.Lookup("valid-token", time.Now()); err == nil {
		t.Fatal("revoked token accepted from cache")
	}
	p.Keys[0].Enabled = true
	p.Keys[0].Expires = time.Now().Add(-time.Second).Unix()
	write(p)
	if _, err := s.Lookup("valid-token", time.Now()); err == nil {
		t.Fatal("expired token accepted")
	}
	_ = os.WriteFile(path, []byte("broken"), 0600)
	if _, err := s.Lookup("valid-token", time.Now()); err == nil {
		t.Fatal("corrupt policy failed open")
	}
}
