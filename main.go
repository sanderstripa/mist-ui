package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var Version = "0.1.0-dev"

//go:embed web/*
var web embed.FS

type Config struct {
	Username   string `json:"username"`
	PassHash   string `json:"pass_hash"`
	Listen     string `json:"listen"`
	WebPath    string `json:"web_path"`
	Cert       string `json:"cert"`
	TLSKey     string `json:"tls_key"`
	ServerFile string `json:"server_file"`
	CoreBinary string `json:"core_binary"`
	StatsFile  string `json:"stats_file"`
}
type Device struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Token     string `json:"token"`
	TokenHash string `json:"token_hash"`
	Address   string `json:"address"`
	Enabled   bool   `json:"enabled"`
	Revoked   bool   `json:"revoked"`
	Expires   int64  `json:"expires"`
	Created   int64  `json:"created"`
}
type State struct {
	Version int      `json:"version"`
	Name    string   `json:"name"`
	DNS     []string `json:"dns"`
	Keys    []Device `json:"keys"`
}
type Session struct {
	CSRF    string
	Expires time.Time
}
type App struct {
	mu       sync.Mutex
	cfg      Config
	state    State
	dir      string
	sessions map[string]Session
	attempts map[string][]time.Time
	control  func(string) (string, error)
}
type Traffic struct {
	RX     uint64 `json:"rx"`
	TX     uint64 `json:"tx"`
	Active bool   `json:"active"`
}

func random(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
func tokenHash(v string) string { s := sha256.Sum256([]byte(v)); return hex.EncodeToString(s[:]) }
func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".mist-write-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	ce := f.Close()
	if err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
	return nil
}
func main() {
	dir := flag.String("data-dir", "/etc/mist-ui", "panel data directory")
	init := flag.Bool("init", false, "initialize panel and adopt an existing MIST server")
	reset := flag.Bool("reset-password", false, "read a new administrator password from stdin")
	username := flag.String("username", "admin", "administrator username")
	listen := flag.String("listen", ":2097", "panel HTTPS listener")
	server := flag.String("server", "/etc/mist/server.json", "existing core config")
	cert := flag.String("cert", "", "HTTPS certificate")
	key := flag.String("key", "", "HTTPS key")
	core := flag.String("core", "/opt/mist/mist-edge", "core binary")
	flag.Parse()
	if *init {
		password, err := io.ReadAll(io.LimitReader(os.Stdin, 100))
		if err != nil {
			log.Fatal(err)
		}
		cfg := Config{Username: *username, Listen: *listen, Cert: *cert, TLSKey: *key, CoreBinary: *core, ServerFile: *server, StatsFile: "/var/lib/mist-ui/stats.json", WebPath: "/" + random(12)}
		if err := initialize(*dir, cfg, strings.TrimSpace(string(password))); err != nil {
			log.Fatal(err)
		}
		var saved Config
		_ = readJSON(filepath.Join(*dir, "config.json"), &saved)
		fmt.Println("Panel path: " + saved.WebPath + "/")
		return
	}
	a, err := loadApp(*dir)
	if err != nil {
		log.Fatal(err)
	}
	if *reset {
		b, _ := io.ReadAll(io.LimitReader(os.Stdin, 100))
		if err = a.setPassword(strings.TrimSpace(string(b))); err != nil {
			log.Fatal(err)
		}
		fmt.Println("Password changed; restart mist-ui.service")
		return
	}
	srv := &http.Server{Addr: a.cfg.Listen, Handler: a.routes(), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	log.Printf("MIST UI %s listening on %s", Version, a.cfg.Listen)
	if a.cfg.Cert == "" || a.cfg.TLSKey == "" {
		log.Fatal("HTTPS certificate and key are required")
	}
	log.Fatal(srv.ListenAndServeTLS(a.cfg.Cert, a.cfg.TLSKey))
}
func validPassword(p string) bool { return len(p) >= 12 && len(p) <= 72 }
func initialize(dir string, cfg Config, password string) error {
	if _, err := os.Stat(filepath.Join(dir, "config.json")); err == nil {
		return errors.New("panel already configured; use --reset-password")
	}
	if !validPassword(password) {
		return errors.New("password must contain 12–72 bytes")
	}
	if cfg.Cert == "" || cfg.TLSKey == "" {
		return errors.New("HTTPS certificate is required")
	}
	var core map[string]any
	if err := readJSON(cfg.ServerFile, &core); err != nil {
		return err
	}
	if v, _ := core["token_secret"].(string); v != "" {
		return errors.New("cannot silently adopt HMAC tokens; migrate them explicitly first")
	}
	if v, _ := core["access_policy_file"].(string); v != "" {
		return errors.New("core already has an access policy; restore existing panel data instead")
	}
	prefix, err := netip.ParsePrefix(str(core, "tun_cidr"))
	if err != nil || !prefix.Addr().Is4() || prefix.Bits() != 24 {
		return errors.New("panel requires an IPv4 /24 tunnel subnet")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	cfg.PassHash = string(h)
	st := State{Version: 1, Name: "MIST", DNS: []string{"1.1.1.1", "1.0.0.1"}, Keys: []Device{}}
	if token := str(core, "token"); token != "" {
		address, err := netip.ParsePrefix(str(core, "client_cidr"))
		if err != nil || !prefix.Contains(address.Addr()) {
			return errors.New("legacy client address is outside tunnel")
		}
		st.Keys = append(st.Keys, Device{ID: random(12), Name: "Существующее устройство", Token: token, TokenHash: tokenHash(token), Address: address.Addr().String(), Enabled: true, Created: time.Now().Unix()})
	}
	if err = writeJSON(filepath.Join(dir, "server-before-panel.json"), core); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "state.json"), st); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "config.json"), cfg); err != nil {
		return err
	}
	core["access_policy_file"] = filepath.Join(dir, "state.json")
	core["stats_file"] = cfg.StatsFile
	delete(core, "token")
	delete(core, "token_secret")
	return writeJSON(cfg.ServerFile, core)
}
func loadApp(dir string) (*App, error) {
	a := &App{dir: dir, sessions: map[string]Session{}, attempts: map[string][]time.Time{}}
	if err := readJSON(filepath.Join(dir, "config.json"), &a.cfg); err != nil {
		return nil, err
	}
	if err := readJSON(filepath.Join(dir, "state.json"), &a.state); err != nil {
		return nil, err
	}
	if a.state.Version != 1 {
		return nil, errors.New("unsupported panel state")
	}
	a.control = func(action string) (string, error) {
		if action != "start" && action != "stop" && action != "restart" && action != "is-active" {
			return "", errors.New("invalid operation")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		b, err := exec.CommandContext(ctx, "systemctl", action, "mist-edge.service").CombinedOutput()
		return strings.TrimSpace(string(b)), err
	}
	return a, nil
}
func str(d map[string]any, key string) string { s, _ := d[key].(string); return s }
func (a *App) persist(next State) error {
	if err := writeJSON(filepath.Join(a.dir, "state.json"), next); err != nil {
		return err
	}
	a.state = next
	return nil
}
func response(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func problem(w http.ResponseWriter, status int, s string) {
	response(w, status, map[string]string{"error": s})
}
func body(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 16384)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		problem(w, 400, "Некорректные данные")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		problem(w, 400, "Лишние данные")
		return false
	}
	return true
}
func (a *App) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/login", a.login)
	mux.HandleFunc("POST /api/logout", a.auth(a.logout))
	mux.HandleFunc("GET /api/state", a.auth(a.getState))
	mux.HandleFunc("POST /api/keys", a.auth(a.createKey))
	mux.HandleFunc("POST /api/keys/{id}/{action}", a.auth(a.keyAction))
	mux.HandleFunc("GET /api/keys/{id}/link", a.auth(a.getLink))
	mux.HandleFunc("GET /api/keys/{id}/qr", a.auth(a.qr))
	mux.HandleFunc("POST /api/service/{action}", a.auth(a.service))
	mux.HandleFunc("POST /api/settings", a.auth(a.settings))
	mux.HandleFunc("POST /api/password", a.auth(a.password))
	mux.HandleFunc("GET /api/logs", a.auth(a.logs))
	sub, _ := fs.Sub(web, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	root := strings.TrimRight(a.cfg.WebPath, "/")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; font-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'")
		w.Header().Set("Cache-Control", "no-store")
		if r.TLS != nil {
			w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		}
		if root != "" {
			if r.URL.Path == root {
				http.Redirect(w, r, root+"/", 307)
				return
			}
			if !strings.HasPrefix(r.URL.Path, root+"/") {
				http.NotFound(w, r)
				return
			}
			r.URL.Path = strings.TrimPrefix(r.URL.Path, root)
		}
		mux.ServeHTTP(w, r)
	})
}
func (a *App) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("mist_session")
		if err != nil {
			problem(w, 401, "Войдите в панель")
			return
		}
		a.mu.Lock()
		s, ok := a.sessions[c.Value]
		if ok && time.Now().After(s.Expires) {
			delete(a.sessions, c.Value)
			ok = false
		}
		a.mu.Unlock()
		if !ok {
			problem(w, 401, "Войдите в панель")
			return
		}
		if r.Method != "GET" && r.Method != "HEAD" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) != 1 {
			problem(w, 403, "CSRF-проверка не пройдена")
			return
		}
		next(w, r)
	}
}
func (a *App) login(w http.ResponseWriter, r *http.Request) {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	a.mu.Lock()
	recent := []time.Time{}
	for _, t := range a.attempts[ip] {
		if now.Sub(t) < time.Minute {
			recent = append(recent, t)
		}
	}
	if len(recent) >= 5 {
		a.mu.Unlock()
		problem(w, 429, "Повторите через минуту")
		return
	}
	if len(a.attempts) > 4096 {
		a.attempts = map[string][]time.Time{}
	}
	a.attempts[ip] = append(recent, now)
	hash, user := a.cfg.PassHash, a.cfg.Username
	a.mu.Unlock()
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !body(w, r, &in) {
		return
	}
	valid := bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) == nil
	valid = valid && subtle.ConstantTimeCompare([]byte(in.Username), []byte(user)) == 1
	if !valid {
		problem(w, 401, "Неверный логин или пароль")
		return
	}
	token, csrf := random(32), random(32)
	a.mu.Lock()
	for id, s := range a.sessions {
		if now.After(s.Expires) {
			delete(a.sessions, id)
		}
	}
	if len(a.sessions) >= 100 {
		a.mu.Unlock()
		problem(w, 429, "Слишком много сеансов")
		return
	}
	a.sessions[token] = Session{csrf, now.Add(12 * time.Hour)}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "mist_session", Value: token, Path: a.cfg.WebPath + "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	response(w, 200, map[string]string{"csrf": csrf})
}
func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("mist_session")
	a.mu.Lock()
	delete(a.sessions, c.Value)
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "mist_session", Path: a.cfg.WebPath + "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	response(w, 200, map[string]bool{"ok": true})
}
func (a *App) getState(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	var core map[string]any
	if err := readJSON(a.cfg.ServerFile, &core); err != nil {
		problem(w, 500, "Не удалось прочитать конфигурацию ядра")
		return
	}
	stats := map[string]Traffic{}
	_ = readJSON(a.cfg.StatsFile, &stats)
	out := []map[string]any{}
	for _, k := range a.state.Keys {
		status := "enabled"
		if !k.Enabled {
			status = "disabled"
		}
		if k.Revoked {
			status = "revoked"
		} else if k.Expires != 0 && time.Now().Unix() >= k.Expires {
			status = "expired"
		}
		out = append(out, map[string]any{"id": k.ID, "name": k.Name, "address": k.Address, "status": status, "expires": k.Expires, "created": k.Created, "traffic": stats[k.Address]})
	}
	status, _ := a.control("is-active")
	c, _ := r.Cookie("mist_session")
	csrf := a.sessions[c.Value].CSRF
	certificateExpiry := ""
	if b, err := os.ReadFile(a.cfg.Cert); err == nil {
		p, _ := pem.Decode(b)
		if p != nil {
			if c, err := x509.ParseCertificate(p.Bytes); err == nil {
				certificateExpiry = c.NotAfter.Format(time.RFC3339)
			}
		}
	}
	response(w, 200, map[string]any{"name": a.state.Name, "dns": a.state.DNS, "keys": out, "service": status, "version": Version, "csrf": csrf, "endpoint": str(core, "authority"), "listen": str(core, "listen"), "certificate_expires": certificateExpiry})
}
func (a *App) createKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
		Days int    `json:"days"`
	}
	if !body(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) < 1 || len(in.Name) > 120 || in.Days < 0 || in.Days > 3650 {
		problem(w, 400, "Введите название и допустимый срок")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	var core map[string]any
	if readJSON(a.cfg.ServerFile, &core) != nil {
		problem(w, 500, "Нет конфигурации MIST")
		return
	}
	p, err := netip.ParsePrefix(str(core, "tun_cidr"))
	if err != nil || p.Bits() != 24 {
		problem(w, 500, "Нужна подсеть /24")
		return
	}
	used := map[string]bool{p.Addr().String(): true}
	for _, k := range a.state.Keys {
		used[k.Address] = true
	}
	base := p.Masked().Addr().As4()
	address := ""
	for i := 2; i < 255; i++ {
		base[3] = byte(i)
		ip := netip.AddrFrom4(base).String()
		if !used[ip] {
			address = ip
			break
		}
	}
	if address == "" {
		problem(w, 409, "Адреса подсети закончились")
		return
	}
	token := random(32)
	k := Device{ID: random(12), Name: in.Name, Token: token, TokenHash: tokenHash(token), Address: address, Enabled: true, Created: time.Now().Unix()}
	if in.Days > 0 {
		k.Expires = time.Now().Add(time.Duration(in.Days) * 24 * time.Hour).Unix()
	}
	next := a.state
	next.Keys = append(append([]Device(nil), next.Keys...), k)
	if err = a.persist(next); err != nil {
		problem(w, 500, "Не удалось сохранить ключ")
		return
	}
	response(w, 201, map[string]string{"id": k.ID})
}
func (a *App) keyAction(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	next := a.state
	next.Keys = append([]Device(nil), next.Keys...)
	for i := range next.Keys {
		if next.Keys[i].ID != r.PathValue("id") {
			continue
		}
		k := &next.Keys[i]
		switch r.PathValue("action") {
		case "disable":
			k.Enabled = false
		case "enable":
			if k.Revoked {
				problem(w, 409, "Отозванный ключ нельзя восстановить")
				return
			}
			k.Enabled = true
		case "revoke":
			k.Enabled = false
			k.Revoked = true
		default:
			problem(w, 400, "Неизвестное действие")
			return
		}
		if err := a.persist(next); err != nil {
			problem(w, 500, "Не удалось изменить ключ")
			return
		}
		response(w, 200, map[string]bool{"ok": true})
		return
	}
	problem(w, 404, "Ключ не найден")
}
func (a *App) clientLink(id string) (string, error) {
	for _, k := range a.state.Keys {
		if k.ID != id {
			continue
		}
		if !k.Enabled || k.Revoked || (k.Expires != 0 && time.Now().Unix() >= k.Expires) {
			return "", errors.New("ключ отключён или истёк")
		}
		var core map[string]any
		if err := readJSON(a.cfg.ServerFile, &core); err != nil {
			return "", err
		}
		authority := str(core, "authority")
		host, _, err := net.SplitHostPort(authority)
		if err != nil {
			host = authority
		}
		ip, err := netip.ParseAddr(host)
		if err != nil || !ip.Is4() {
			return "", errors.New("панель использует IPv4 адрес в authority")
		}
		_, port, err := net.SplitHostPort(str(core, "listen"))
		if err != nil {
			return "", err
		}
		client := map[string]any{"endpoint": map[string]string{"authority": authority, "dial_address": net.JoinHostPort(ip.String(), port), "path": str(core, "path")}, "token": k.Token, "tun_name": "MIST", "mtu": core["mtu"], "dns": a.state.DNS, "h2_fallback": true, "fallback_client_cidr": k.Address + "/32", "inner_quic_policy": "auto", "mss_clamp": 1200, "pmtu_mode": "auto", "kill_switch": "fail_closed", "ipv6_mode": "block", "wire_profile": "native"}
		b, err := json.Marshal(client)
		if err != nil {
			return "", err
		}
		return "mist://" + base64.RawURLEncoding.EncodeToString(b), nil
	}
	return "", errors.New("ключ не найден")
}
func (a *App) getLink(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	link, err := a.clientLink(r.PathValue("id"))
	if err != nil {
		problem(w, 404, err.Error())
		return
	}
	response(w, 200, map[string]string{"link": link})
}
func (a *App) qr(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	link, err := a.clientLink(r.PathValue("id"))
	a.mu.Unlock()
	if err != nil {
		problem(w, 404, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "qrencode", "-t", "PNG", "-o", "-", "--", link).Output()
	if err != nil {
		problem(w, 500, "QR-код недоступен")
		return
	}
	w.Header().Set("Content-Type", "image/png")
	_, _ = w.Write(b)
}
func (a *App) service(w http.ResponseWriter, r *http.Request) {
	action := r.PathValue("action")
	if action != "start" && action != "stop" && action != "restart" {
		problem(w, 400, "Неизвестное действие")
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, err := a.control(action); err != nil {
		problem(w, 500, "Операция MIST не выполнена; проверьте журнал")
		return
	}
	response(w, 200, map[string]bool{"ok": true})
}
func (a *App) settings(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string   `json:"name"`
		DNS  []string `json:"dns"`
		Port int      `json:"port"`
	}
	if !body(w, r, &in) {
		return
	}
	in.Name = strings.TrimSpace(in.Name)
	if len(in.Name) < 1 || len(in.Name) > 120 || len(in.DNS) < 1 || len(in.DNS) > 4 {
		problem(w, 400, "Проверьте название и DNS")
		return
	}
	for _, s := range in.DNS {
		ip, err := netip.ParseAddr(s)
		if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() {
			problem(w, 400, "Укажите IPv4 DNS-серверы")
			return
		}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if in.Port < 0 || in.Port > 65535 {
		problem(w, 400, "Некорректный порт")
		return
	}
	var oldCore map[string]any
	if err := readJSON(a.cfg.ServerFile, &oldCore); err != nil {
		problem(w, 500, "Конфигурация ядра недоступна")
		return
	}
	bind, oldPort, _ := net.SplitHostPort(str(oldCore, "listen"))
	changed := in.Port > 0 && strconv.Itoa(in.Port) != oldPort
	rollbackCore := func() { _ = writeJSON(a.cfg.ServerFile, oldCore); _, _ = a.control("restart") }
	if changed {
		_, panelPort, _ := net.SplitHostPort(a.cfg.Listen)
		if strconv.Itoa(in.Port) == panelPort {
			problem(w, 409, "Этот порт занят панелью")
			return
		}
		address := net.JoinHostPort(bind, strconv.Itoa(in.Port))
		tcp, err := net.Listen("tcp", address)
		if err != nil {
			problem(w, 409, "TCP-порт занят")
			return
		}
		udp, err := net.ListenPacket("udp", address)
		_ = tcp.Close()
		if err != nil {
			problem(w, 409, "UDP-порт занят")
			return
		}
		_ = udp.Close()
		nextCore := make(map[string]any)
		for k, v := range oldCore {
			nextCore[k] = v
		}
		nextCore["listen"] = address
		if host, _, err := net.SplitHostPort(str(oldCore, "authority")); err == nil {
			nextCore["authority"] = net.JoinHostPort(host, strconv.Itoa(in.Port))
		}
		if err = writeJSON(a.cfg.ServerFile, nextCore); err != nil {
			problem(w, 500, "Не удалось изменить порт")
			return
		}
		status, _ := a.control("is-active")
		if status == "active" {
			if _, err = a.control("restart"); err != nil {
				rollbackCore()
				problem(w, 500, "Перезапуск не удался; настройки восстановлены")
				return
			}
			time.Sleep(time.Second)
			if status, _ = a.control("is-active"); status != "active" {
				rollbackCore()
				problem(w, 500, "Новый порт не заработал; настройки восстановлены")
				return
			}
		}
	}
	next := a.state
	next.Name = in.Name
	next.DNS = in.DNS
	if err := a.persist(next); err != nil {
		if changed {
			rollbackCore()
		}
		problem(w, 500, "Не удалось сохранить")
		return
	}
	response(w, 200, map[string]bool{"ok": true})
}
func (a *App) setPassword(p string) error {
	if !validPassword(p) {
		return errors.New("пароль: 12–72 байта")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(p), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	next := a.cfg
	next.PassHash = string(h)
	if err = writeJSON(filepath.Join(a.dir, "config.json"), next); err != nil {
		return err
	}
	a.cfg = next
	a.sessions = map[string]Session{}
	return nil
}
func (a *App) password(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if !body(w, r, &in) {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if bcrypt.CompareHashAndPassword([]byte(a.cfg.PassHash), []byte(in.Current)) != nil {
		problem(w, 403, "Текущий пароль неверен")
		return
	}
	if err := a.setPassword(in.New); err != nil {
		problem(w, 400, err.Error())
		return
	}
	response(w, 200, map[string]bool{"ok": true})
}
func (a *App) logs(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, "journalctl", "-u", "mist-edge.service", "-n", "100", "--no-pager", "-o", "short-iso").Output()
	if err != nil {
		problem(w, 500, "Журнал недоступен")
		return
	}
	lines := strings.Split(string(b), "\n")
	for i, line := range lines {
		if strings.Contains(strings.ToLower(line), "token") || strings.Contains(line, "Bearer ") {
			lines[i] = "[секрет скрыт]"
		}
	}
	response(w, 200, map[string]string{"logs": strings.Join(lines, "\n")})
}

// Keep the listener port validator available to installer / regression checks.
func validPort(s string) bool { n, err := strconv.Atoi(s); return err == nil && n > 0 && n < 65536 }
