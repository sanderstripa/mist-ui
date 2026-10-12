package h2frame

import (
	"bytes"
	"testing"
)

func TestRoundTripPaddedFrame(t *testing.T) {
	packet := make([]byte, 1200)
	for i := range packet {
		packet[i] = byte(i)
	}
	var b bytes.Buffer
	if err := Write(&b, packet, true); err != nil {
		t.Fatal(err)
	}
	if got, want := b.Len(), 4+1280; got != want {
		t.Fatalf("frame length = %d, want %d", got, want)
	}
	out := make([]byte, 1500)
	n, err := Read(&b, out)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(packet) {
		t.Fatalf("packet length = %d, want %d", n, len(packet))
	}
	if !bytes.Equal(out[:n], packet) {
		t.Fatal("packet changed after round trip")
	}
}

func TestPaddedLength(t *testing.T) {
	cases := map[int]int{1:256, 256:256, 257:512, 1000:1024, 1280:1280, 1400:1536, 2000:2000}
	for in, want := range cases {
		if got := PaddedLength(in); got != want {
			t.Fatalf("PaddedLength(%d) = %d, want %d", in, got, want)
		}
	}
}
