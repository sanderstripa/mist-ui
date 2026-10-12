package ratelimit

import (
	"testing"
	"time"
)

func TestLimiter(t *testing.T) {
	l := New(2, time.Minute)
	now := time.Unix(1000, 0)
	if !l.Allow("a", now) || !l.Allow("a", now.Add(time.Second)) { t.Fatal("first two requests should pass") }
	if l.Allow("a", now.Add(2*time.Second)) { t.Fatal("third request should be limited") }
	if !l.Allow("b", now.Add(2*time.Second)) { t.Fatal("independent source should pass") }
	if !l.Allow("a", now.Add(61*time.Second)) { t.Fatal("new window should pass") }
}
