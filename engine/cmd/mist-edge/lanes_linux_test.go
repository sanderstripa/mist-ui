//go:build linux

package main

import "testing"

func TestLaneOutputBoundedBackpressureAndClose(t *testing.T) {
	out := &laneOutput{queue: make(chan []byte, 1), done: make(chan struct{})}
	if !out.enqueue([]byte{1}) {
		t.Fatal("first packet should fit in lane queue")
	}
	if out.enqueue([]byte{2}) {
		t.Fatal("full lane queue should eventually reject after bounded backpressure")
	}

	<-out.queue
	if !out.enqueue([]byte{3}) {
		t.Fatal("lane should accept packet after queue drains")
	}
	<-out.queue

	out.closeQueue()
	if out.enqueue([]byte{4}) {
		t.Fatal("closed lane accepted packet")
	}
}
