package main

import (
	"net"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestPortConflictsDoNotChangeWorkingServer(t *testing.T) {
	a := testApp(t)
	server := httptest.NewTLSServer(a.routes())
	defer server.Close()
	s := apiTest{t: t, server: server}
	s.login()
	socket, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	port := socket.Addr().(*net.TCPAddr).Port
	if code, _ := s.request("settings", "POST", `{"name":"changed","dns":["1.1.1.1"],"port":`+strconv.Itoa(port)+`}`); code != 409 {
		t.Fatal("occupied listener accepted")
	}
	var cfg map[string]any
	_ = readJSON(a.cfg.ServerFile, &cfg)
	if cfg["listen"] != ":443" || a.state.Name != "MIST" {
		t.Fatal("conflict changed config")
	}
	if code, _ := s.request("settings", "POST", `{"name":"changed","dns":["1.1.1.1"],"port":80}`); code != 400 {
		t.Fatal("ACME port accepted")
	}
}
