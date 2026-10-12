package streambuf

import (
	"bytes"
	"testing"
	"time"
)

func TestFlushHookRunsOnlyForBufferedPayload(t *testing.T) {
	var dst bytes.Buffer
	hooks := 0
	w := New(&dst, 1024, time.Hour, func() { hooks++ })
	defer w.Close()

	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if hooks != 0 {
		t.Fatalf("empty flush invoked hook %d times", hooks)
	}

	if _, err := w.Write([]byte("payload")); err != nil {
		t.Fatal(err)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if hooks != 1 {
		t.Fatalf("payload flush hook count=%d, want 1", hooks)
	}
	if got := dst.String(); got != "payload" {
		t.Fatalf("payload=%q", got)
	}

	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if hooks != 1 {
		t.Fatalf("second empty flush invoked hook; count=%d", hooks)
	}
}
