package flowhash

import "testing"

func TestReverseTCPFlowUsesSameLane(t *testing.T) {
	a := []byte{
		0x45,0,0,40,0,0,0,0,64,6,0,0,
		10,0,0,2, 1,1,1,1,
		0x30,0x39, 0x01,0xbb,
	}
	b := []byte{
		0x45,0,0,40,0,0,0,0,64,6,0,0,
		1,1,1,1, 10,0,0,2,
		0x01,0xbb, 0x30,0x39,
	}
	if got, want := Index(a, 8), Index(b, 8); got != want {
		t.Fatalf("forward lane %d != reverse lane %d", got, want)
	}
}
