package streambuf

import (
	"bufio"
	"errors"
	"io"
	"sync"
	"time"
)

// Writer batches many small packet records into larger writes. A short periodic
// flush bounds interactive latency while the buffer-size flush keeps throughput
// high under sustained load.
type Writer struct {
	mu        sync.Mutex
	bw        *bufio.Writer
	flushHook func()
	stop      chan struct{}
	done      chan struct{}
	err       error
}

func New(w io.Writer, size int, interval time.Duration, flushHook func()) *Writer {
	if size <= 0 {
		size = 64 << 10
	}
	if interval <= 0 {
		interval = time.Millisecond
	}
	x := &Writer{
		bw:        bufio.NewWriterSize(w, size),
		flushHook: flushHook,
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	go x.flushLoop(interval)
	return x
}

func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.err != nil {
		return 0, w.err
	}
	n, err := w.bw.Write(p)
	if err != nil {
		w.err = err
	}
	return n, err
}

func (w *Writer) flushLocked() error {
	if w.err != nil {
		return w.err
	}
	// A periodic tick used to call the HTTP/3 flush hook even when there was no
	// buffered payload. For long-lived lanes that meant up to 1,000 empty HTTP
	// flushes per second per lane. Besides wasting CPU, this can force the H3
	// response path into tiny writes. Only flush the transport when there is
	// actual packet data waiting.
	if w.bw.Buffered() == 0 {
		return nil
	}
	if err := w.bw.Flush(); err != nil {
		w.err = err
		return err
	}
	if w.flushHook != nil {
		w.flushHook()
	}
	return nil
}

func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

func (w *Writer) Close() error {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.flushLocked()
}

func (w *Writer) flushLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	defer close(w.done)
	for {
		select {
		case <-ticker.C:
			_ = w.Flush()
		case <-w.stop:
			return
		}
	}
}

func (w *Writer) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.err
}

var _ io.WriteCloser = (*Writer)(nil)

func JoinClose(errs ...error) error {
	return errors.Join(errs...)
}
