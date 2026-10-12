package ratelimit

import (
	"sync"
	"time"
)

type entry struct {
	window time.Time
	count  int
}

type Limiter struct {
	mu     sync.Mutex
	limit  int
	window time.Duration
	items  map[string]entry
	calls  uint64
}

func New(limit int, window time.Duration) *Limiter {
	if limit < 1 { limit = 1 }
	return &Limiter{limit: limit, window: window, items: make(map[string]entry)}
}

func (l *Limiter) Allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if l.calls%1024 == 0 { l.pruneLocked(now) }
	e := l.items[key]
	if e.window.IsZero() || now.Sub(e.window) >= l.window {
		l.items[key] = entry{window: now, count: 1}
		return true
	}
	if e.count >= l.limit { return false }
	e.count++
	l.items[key] = e
	return true
}

func (l *Limiter) pruneLocked(now time.Time) {
	for k, e := range l.items {
		if now.Sub(e.window) >= 2*l.window { delete(l.items, k) }
	}
}
