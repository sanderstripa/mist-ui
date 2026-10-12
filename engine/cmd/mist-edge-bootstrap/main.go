package main

import (
	"context"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	cip "github.com/quic-go/connect-ip-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
	"golang.zx2c4.com/wireguard/tun"
)

type Config struct {
	Listen        string `json:"listen"`
	Authority     string `json:"authority"`
	Path          string `json:"path"`
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"private_key"`
	Token         string `json:"token"`
	TUNName       string `json:"tun_name"`
	TUNCIDR       string `json:"tun_cidr"`
	ClientCIDR    string `json:"client_cidr"`
	AdvertiseCIDR string `json:"advertise_cidr"`
	MTU           int    `json:"mtu"`
	EnableNAT     bool   `json:"enable_nat"`
}

func run(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func ensureIptables(args ...string) error {
	check := append([]string{}, args...)
	if len(check) > 0 && check[0] == "-t" {
		check = append(check[:2], append([]string{"-C"}, check[2:]...)...)
	} else {
		check = append([]string{"-C"}, check...)
	}
	if exec.Command("iptables", check...).Run() == nil {
		return nil
	}
	add := append([]string{}, args...)
	if len(add) > 0 && add[0] == "-t" {
		add = append(add[:2], append([]string{"-A"}, add[2:]...)...)
	} else {
		add = append([]string{"-A"}, add...)
	}
	return run("iptables", add...)
}

func lastIP(prefix netip.Prefix) netip.Addr {
	p := prefix.Masked()
	a := p.Addr().As4()
	v := binary.BigEndian.Uint32(a[:])
	hostBits := uint(32 - p.Bits())
	if hostBits == 32 {
		v = ^uint32(0)
	} else if hostBits > 0 {
		v |= (uint32(1) << hostBits) - 1
	}
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], v)
	return netip.AddrFrom4(out)
}

func validBearer(header, want string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return false
	}
	got := strings.TrimPrefix(header, prefix)
	return len(got) == len(want) && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func serveSite(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if r.URL.Path != "/" || r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	_, _ = fmt.Fprint(w, "<!doctype html><title>Welcome</title><h1>Welcome</h1><p>Service is online.</p>")
}

func shouldProxyEdgePacket(packet []byte) bool {
	if len(packet) < 20 || packet[0]>>4 != 4 {
		return false
	}
	// CONNECT-IP decrements TTL before proxying. Locally scoped packets with a
	// TTL of 1 must never leave the virtual link.
	if packet[8] <= 1 {
		return false
	}
	src := netip.AddrFrom4([4]byte(packet[12:16]))
	dst := netip.AddrFrom4([4]byte(packet[16:20]))
	if src.IsUnspecified() || src.IsLoopback() || src.IsLinkLocalUnicast() || src.IsMulticast() {
		return false
	}
	if dst.IsUnspecified() || dst.IsLoopback() || dst.IsLinkLocalUnicast() || dst.IsMulticast() || dst == netip.MustParseAddr("255.255.255.255") {
		return false
	}
	return true
}

const tunPacketOffset = 10

func writeTunPacket(dev tun.Device, packet []byte) error {
	buf := make([]byte, tunPacketOffset+len(packet))
	copy(buf[tunPacketOffset:], packet)
	_, err := dev.Write([][]byte{buf}, tunPacketOffset)
	return err
}

func bridge(conn *cip.Conn, dev tun.Device, mtu int) error {
	errCh := make(chan error, 2)

	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := conn.ReadPacket(buf)
			if err != nil {
				errCh <- fmt.Errorf("read CONNECT-IP: %w", err)
				return
			}
			packet := append([]byte(nil), buf[:n]...)
			if err := writeTunPacket(dev, packet); err != nil {
				errCh <- fmt.Errorf("inject packet into mist0: %w", err)
				return
			}
		}
	}()

	go func() {
		batch := dev.BatchSize()
		for {
			bufs := make([][]byte, batch)
			sizes := make([]int, batch)
			for i := range bufs {
				bufs[i] = make([]byte, tunPacketOffset+mtu+256)
			}
			n, err := dev.Read(bufs, sizes, tunPacketOffset)
			if err != nil {
				errCh <- fmt.Errorf("read mist0: %w", err)
				return
			}
			for i := 0; i < n; i++ {
				packet := append([]byte(nil), bufs[i][tunPacketOffset:tunPacketOffset+sizes[i]]...)
				if !shouldProxyEdgePacket(packet) {
					continue
				}
				icmp, err := conn.WritePacket(packet)
				if err != nil {
					errCh <- fmt.Errorf("write CONNECT-IP: %w", err)
					return
				}
				if len(icmp) > 0 {
					_ = writeTunPacket(dev, icmp)
				}
			}
		}
	}()

	return <-errCh
}

func main() {
	configPath := flag.String("config", "/etc/mist/server.json", "path to config")
	flag.Parse()

	raw, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatal(err)
	}
	var cfg Config
	if err := json.Unmarshal(raw, &cfg); err != nil {
		log.Fatalf("bad config: %v", err)
	}

	clientPrefix := netip.MustParsePrefix(cfg.ClientCIDR)
	routePrefix := netip.MustParsePrefix(cfg.AdvertiseCIDR)

	dev, err := tun.CreateTUN(cfg.TUNName, cfg.MTU)
	if err != nil {
		log.Fatal(err)
	}
	defer dev.Close()
	tunName, _ := dev.Name()

	if err := run("ip", "link", "set", "dev", tunName, "up"); err != nil { log.Fatal(err) }
	if err := run("ip", "addr", "replace", cfg.TUNCIDR, "dev", tunName); err != nil { log.Fatal(err) }
	if err := run("ip", "link", "set", "dev", tunName, "mtu", fmt.Sprint(cfg.MTU)); err != nil { log.Fatal(err) }
	_ = run("sysctl", "-w", "net.ipv6.conf."+tunName+".disable_ipv6=1")
	if err := run("sysctl", "-w", "net.ipv4.ip_forward=1"); err != nil { log.Fatal(err) }

	if cfg.EnableNAT {
		if err := ensureIptables("-t", "nat", "POSTROUTING", "-s", cfg.TUNCIDR, "-j", "MASQUERADE"); err != nil { log.Fatal(err) }
		if err := ensureIptables("FORWARD", "-i", tunName, "-j", "ACCEPT"); err != nil { log.Fatal(err) }
		if err := ensureIptables("FORWARD", "-o", tunName, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"); err != nil { log.Fatal(err) }
	}

	cert, err := tls.LoadX509KeyPair(cfg.Certificate, cfg.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	template := uritemplate.MustNew("https://" + cfg.Authority + cfg.Path)
	proxy := cip.Proxy{}
	var active atomic.Bool

	h3Mux := http.NewServeMux()
	h3Mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != cfg.Path || r.Method != http.MethodConnect {
			serveSite(w, r)
			return
		}
		if !validBearer(r.Header.Get("Authorization"), cfg.Token) || !active.CompareAndSwap(false, true) {
			http.NotFound(w, r)
			return
		}
		defer active.Store(false)

		req, err := cip.ParseProxyRequest(r, template)
		if err != nil {
			var parseErr *cip.ProxyRequestParseError
			if errors.As(err, &parseErr) {
				w.WriteHeader(parseErr.HTTPStatus)
			} else {
				http.NotFound(w, r)
			}
			log.Printf("MIST: CONNECT-IP parse failed: %v", err)
			return
		}
		conn, err := proxy.Proxy(w, req)
		if err != nil {
			log.Printf("MIST: CONNECT-IP accept failed: %v", err)
			return
		}
		defer conn.Close()

		if err := conn.AssignAddresses([]netip.Prefix{clientPrefix}); err != nil {
			log.Printf("MIST: address assignment failed: %v", err)
			return
		}
		if err := conn.AdvertiseRoute([]cip.IPRoute{{StartIP: routePrefix.Masked().Addr(), EndIP: lastIP(routePrefix), IPProtocol: 0}}); err != nil {
			log.Printf("MIST: route advertisement failed: %v", err)
			return
		}

		log.Printf("MIST: client connected; assigned=%s", clientPrefix)
		err = bridge(conn, dev, cfg.MTU)
		log.Printf("MIST: client disconnected; reason=%v", err)
	})

	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	h3 := &http3.Server{
		Addr: cfg.Listen,
		TLSConfig: tlsConfig,
		QUICConfig: &quic.Config{EnableDatagrams: true, MaxIdleTimeout: 60 * time.Second, KeepAlivePeriod: 20 * time.Second},
		Handler: h3Mux,
		EnableDatagrams: true,
	}
	web := &http.Server{Addr: cfg.Listen, Handler: http.HandlerFunc(serveSite), TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13}}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		if err := web.ListenAndServeTLS(cfg.Certificate, cfg.PrivateKey); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("MIST: TCP HTTPS server stopped: %v", err)
			stop()
		}
	}()
	go func() {
		if err := h3.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Printf("MIST: HTTP/3 server stopped: %v", err)
			stop()
		}
	}()

	log.Printf("MIST: edge ready; authority=%s listen=%s tun=%s", cfg.Authority, cfg.Listen, tunName)
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = web.Shutdown(shutdownCtx)
	_ = h3.Shutdown(shutdownCtx)
}
