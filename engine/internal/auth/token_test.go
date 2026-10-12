package auth

import (
	"testing"
	"time"
)

func TestTokenLifecycle(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	secret := "0123456789abcdef0123456789abcdef"
	tok, err := Mint(secret, "client-a", now, 15*time.Minute)
	if err != nil { t.Fatal(err) }
	id, err := Verify(secret, tok, now.Add(time.Minute))
	if err != nil { t.Fatal(err) }
	if id != "client-a" { t.Fatalf("id=%q", id) }
	if _, err := Verify(secret, tok, now.Add(16*time.Minute)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err := Verify("fedcba9876543210fedcba9876543210", tok, now); err == nil {
		t.Fatal("wrong secret accepted")
	}
}
