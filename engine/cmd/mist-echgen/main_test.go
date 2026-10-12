package main

import (
	"encoding/binary"
	"testing"
)

func TestBuildECHConfigEncoding(t *testing.T) {
	pub := make([]byte, 32)
	for i := range pub {
		pub[i] = byte(i + 1)
	}
	config, list, err := buildECHConfig(7, pub, 32, "cover.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(config[:2]); got != echVersion {
		t.Fatalf("version = %#x", got)
	}
	if got := int(binary.BigEndian.Uint16(config[2:4])); got != len(config)-4 {
		t.Fatalf("config length = %d, want %d", got, len(config)-4)
	}
	if got := int(binary.BigEndian.Uint16(list[:2])); got != len(config) {
		t.Fatalf("list length = %d, want %d", got, len(config))
	}
	if string(list[2:]) != string(config) {
		t.Fatal("ECHConfigList payload differs from ECHConfig")
	}
}

func TestValidatePublicName(t *testing.T) {
	if err := validatePublicName("cover.example.com"); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", ".example.com", "example.com.", "-bad.example", "bad_.example"} {
		if err := validatePublicName(bad); err == nil {
			t.Fatalf("%q unexpectedly accepted", bad)
		}
	}
}
