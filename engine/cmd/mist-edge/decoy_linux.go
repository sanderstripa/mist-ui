//go:build linux

package main

import (
	"net/http"
	"sync"
)

var (
	decoyMu      sync.RWMutex
	decoyHandler http.Handler = http.HandlerFunc(defaultDecoy)
)

func configureDecoy(root string) {
	decoyMu.Lock()
	defer decoyMu.Unlock()
	if root == "" {
		decoyHandler = http.HandlerFunc(defaultDecoy)
		return
	}
	decoyHandler = http.FileServer(http.Dir(root))
}

func serveDecoyContent(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Alt-Svc", `h3=":443"; ma=86400`)
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	decoyMu.RLock()
	h := decoyHandler
	decoyMu.RUnlock()
	h.ServeHTTP(w, r)
}

func defaultDecoy(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path != "/" || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
		http.NotFound(w, r)
		return
	}
	if r.Method == http.MethodHead {
		w.WriteHeader(http.StatusOK)
		return
	}
	_, _ = w.Write([]byte("<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Welcome</title></head><body><main><h1>Welcome</h1><p>Service is online.</p></main></body></html>"))
}
