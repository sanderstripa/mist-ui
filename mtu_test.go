package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestProfileRespectsSmallerServerMTU(t *testing.T) {
	a := testApp(t)
	var core map[string]any
	_ = readJSON(a.cfg.ServerFile, &core)
	core["mtu"] = 1200
	_ = writeJSON(a.cfg.ServerFile, core)
	a.state.Keys = []Device{{ID: "device", Token: "mtu-test-key", Enabled: true, Address: "10.77.43.2"}}
	link, err := a.clientLink("device")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(link, "mist://"))
	if err != nil {
		t.Fatal(err)
	}
	var client map[string]any
	_ = json.Unmarshal(raw, &client)
	if client["mtu"] != float64(1200) {
		t.Fatal("server MTU changed")
	}
	if _, ok := client["mss_clamp"]; ok {
		t.Fatal("profile overrides client's safe MTU-dependent MSS default")
	}
}
