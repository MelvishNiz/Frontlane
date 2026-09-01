package main

import (
	"crypto/rand"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/argon2"
)

//go:embed web/templates/*.html web/static/*
var assets embed.FS

var peerNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$`)

type config struct {
	Listen         string
	PublicEndpoint string
	BaseDomain     string
	ACMEEmail      string
	AdminUser      string
	AdminPassword  string
	CookieSecure   bool
	DataDir        string
	WGDir          string
	CaddyFile      string
	CoreDNSHosts   string
}

type server struct {
	cfg      config
	store    *store
	tpl      *template.Template
	sessions map[string]session
	attempts map[string][]time.Time
	mu       sync.Mutex
}

type session struct {
	CSRF    string
	Expires time.Time
}

type viewData struct {
	Title        string
	User         string
	CSRF         string
	Error        string
	Notice       string
	Peers        []peer
	Services     []service
	WG           wgStatus
	Config       string
	PanelDomain  string
	BaseDomain   string
	Endpoint     string
	Peer         peer
	PeerCreated  bool
	ConfigStored bool
}

func main() {
	cfg := loadConfig()
	if cfg.PublicEndpoint == "" || cfg.BaseDomain == "" || cfg.ACMEEmail == "" {
		log.Fatal("PWG_PUBLIC_ENDPOINT, PWG_BASE_DOMAIN, and PWG_ACME_EMAIL are required")
	}
	st, err := openStore(cfg.DataDir + "/privatewg.db")
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	if err := st.ensureAdmin(cfg.AdminUser, cfg.AdminPassword); err != nil {
		log.Fatal(err)
	}

	tpl, err := template.New("").Funcs(template.FuncMap{
		"bytes":   humanBytes,
		"ago":     timeAgo,
		"initial": initial,
		"internalDomain": func(host string) bool {
			return host == cfg.BaseDomain || strings.HasSuffix(host, "."+cfg.BaseDomain)
		},
	}).ParseFS(assets, "web/templates/*.html")
	if err != nil {
		log.Fatal(err)
	}

	s := &server{cfg: cfg, store: st, tpl: tpl, sessions: map[string]session{}, attempts: map[string][]time.Time{}}
	if err := s.ensureWireGuard(); err != nil {
		log.Fatalf("wireguard setup: %v", err)
	}
	if err := s.ensureBootstrapPeer(); err != nil {
		log.Fatalf("bootstrap peer: %v", err)
	}
	if err := s.writeRoutingFiles(); err != nil {
		log.Fatalf("routing config: %v", err)
	}

	staticFS, err := fs.Sub(assets, "web/static")
	if err != nil {
		log.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))
	mux.HandleFunc("GET /login", s.loginPage)
	mux.HandleFunc("POST /login", s.login)
	mux.HandleFunc("POST /logout", s.auth(s.logout))
	mux.HandleFunc("GET /", s.auth(s.dashboard))
	mux.HandleFunc("GET /peers", s.auth(s.peersPage))
	mux.HandleFunc("POST /peers", s.auth(s.createPeer))
	mux.HandleFunc("GET /peers/{id}", s.auth(s.peerDetail))
	mux.HandleFunc("GET /peers/{id}/config", s.auth(s.downloadPeerConfig))
	mux.HandleFunc("GET /peers/{id}/qr.png", s.auth(s.peerQRCode))
	mux.HandleFunc("POST /peers/{id}/toggle", s.auth(s.togglePeer))
	mux.HandleFunc("POST /peers/{id}/delete", s.auth(s.deletePeer))
	mux.HandleFunc("GET /services", s.auth(s.servicesPage))
	mux.HandleFunc("POST /services", s.auth(s.createService))
	mux.HandleFunc("POST /services/{id}/toggle", s.auth(s.toggleService))
	mux.HandleFunc("POST /services/{id}/delete", s.auth(s.deleteService))

	h := securityHeaders(mux)
	log.Printf("PrivateWG listening on %s; panel domain https://panel.%s", cfg.Listen, cfg.BaseDomain)
	if err := http.ListenAndServe(cfg.Listen, h); err != nil {
		log.Fatal(err)
	}
}

func loadConfig() config {
	return config{
		Listen:         env("PWG_LISTEN", "10.77.0.1:8080"),
		PublicEndpoint: os.Getenv("PWG_PUBLIC_ENDPOINT"),
		BaseDomain:     strings.TrimSuffix(os.Getenv("PWG_BASE_DOMAIN"), "."),
		ACMEEmail:      os.Getenv("PWG_ACME_EMAIL"),
		AdminUser:      env("PWG_ADMIN_USER", "admin"),
		AdminPassword:  os.Getenv("PWG_ADMIN_PASSWORD"),
		CookieSecure:   env("PWG_COOKIE_SECURE", "true") == "true",
		DataDir:        env("PWG_DATA_DIR", "/data/privatewg"),
		WGDir:          env("PWG_WG_DIR", "/etc/wireguard"),
		CaddyFile:      env("PWG_CADDY_FILE", "/data/caddy/Caddyfile"),
		CoreDNSHosts:   env("PWG_COREDNS_HOSTS", "/data/coredns/domains.hosts"),
	}
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func (s *server) loginPage(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.currentSession(r); ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", viewData{Title: "Masuk"})
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if s.rateLimited(ip) {
		s.renderStatus(w, "login.html", viewData{Title: "Masuk", Error: "Terlalu banyak percobaan. Coba lagi dalam 15 menit."}, http.StatusTooManyRequests)
		return
	}
	if err := r.ParseForm(); err != nil || !s.store.authenticate(r.FormValue("username"), r.FormValue("password")) {
		s.recordFailure(ip)
		s.renderStatus(w, "login.html", viewData{Title: "Masuk", Error: "Username atau password tidak cocok."}, http.StatusUnauthorized)
		return
	}
	token := randomToken(32)
	s.mu.Lock()
	s.sessions[token] = session{CSRF: randomToken(24), Expires: time.Now().Add(12 * time.Hour)}
	delete(s.attempts, ip)
	s.mu.Unlock()
	s.store.audit("login", s.cfg.AdminUser, ip)
	http.SetCookie(w, &http.Cookie{Name: "pwg_session", Value: token, Path: "/", MaxAge: 43200, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *server) logout(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "CSRF token tidak valid", http.StatusForbidden)
		return
	}
	if cookie, err := r.Cookie("pwg_session"); err == nil {
		s.mu.Lock()
		delete(s.sessions, cookie.Value)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: "pwg_session", Path: "/", MaxAge: -1, HttpOnly: true, Secure: s.cfg.CookieSecure, SameSite: http.SameSiteStrictMode})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *server) dashboard(w http.ResponseWriter, r *http.Request) {
	peers, _ := s.store.listPeers()
	services, _ := s.store.listServices()
	status, _ := s.wireGuardStatus(peers)
	s.render(w, "dashboard.html", s.data(r, "Ringkasan", peers, services, status))
}

func (s *server) peersPage(w http.ResponseWriter, r *http.Request) {
	peers, _ := s.store.listPeers()
	status, _ := s.wireGuardStatus(peers)
	s.render(w, "peers.html", s.data(r, "Peer", peers, nil, status))
}

func (s *server) createPeer(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "CSRF token tidak valid", http.StatusForbidden)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	kind := r.FormValue("kind")
	if !peerNamePattern.MatchString(name) || (kind != "client" && kind != "server") {
		s.peerError(w, r, "Nama atau jenis peer tidak valid.", http.StatusBadRequest)
		return
	}
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		s.peerError(w, r, err.Error(), http.StatusInternalServerError)
		return
	}
	p, err := s.store.createPeer(name, kind, publicKey)
	if err != nil {
		s.peerError(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.applyWireGuard(); err != nil {
		_ = s.store.deletePeer(p.ID)
		s.peerError(w, r, "WireGuard menolak konfigurasi baru: "+err.Error(), http.StatusInternalServerError)
		return
	}
	clientConfig := s.clientConfig(p, privateKey)
	if err := s.storeEncryptedConfig(p.ID, clientConfig); err != nil {
		_ = s.store.deletePeer(p.ID)
		_ = s.applyWireGuard()
		s.peerError(w, r, "Config peer gagal disimpan: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.audit("peer.create", p.Name+" "+p.IP, clientIP(r))
	http.Redirect(w, r, fmt.Sprintf("/peers/%d?created=1", p.ID), http.StatusSeeOther)
}

func (s *server) peerDetail(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	peers, err := s.store.listPeers()
	if err != nil {
		http.Error(w, "Peer gagal dimuat", http.StatusInternalServerError)
		return
	}
	status, _ := s.wireGuardStatus(peers)
	var selected *peer
	for i := range peers {
		if peers[i].ID == id {
			selected = &peers[i]
			break
		}
	}
	if selected == nil {
		http.NotFound(w, r)
		return
	}
	data := s.data(r, "Detail peer", peers, nil, status)
	data.Peer = *selected
	data.PeerCreated = r.URL.Query().Get("created") == "1"
	data.ConfigStored = selected.HasConfig
	if selected.HasConfig {
		data.Config, err = s.decryptedPeerConfig(*selected)
		if err != nil {
			data.Error = err.Error()
			data.ConfigStored = false
		}
	}
	s.render(w, "peer-created.html", data)
}

func (s *server) downloadPeerConfig(w http.ResponseWriter, r *http.Request) {
	p, config, ok := s.peerConfigResponse(w, r)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/x-wireguard-profile")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.conf"`, p.Name))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	s.store.audit("peer.config.download", p.Name+" "+p.IP, clientIP(r))
	_, _ = w.Write([]byte(config))
}

func (s *server) peerQRCode(w http.ResponseWriter, r *http.Request) {
	_, config, ok := s.peerConfigResponse(w, r)
	if !ok {
		return
	}
	png, err := qrPNG(config)
	if err != nil {
		http.Error(w, "QR code gagal dibuat", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Content-Length", strconv.Itoa(len(png)))
	_, _ = w.Write(png)
}

func (s *server) peerConfigResponse(w http.ResponseWriter, r *http.Request) (peer, string, bool) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return peer{}, "", false
	}
	p, err := s.store.peerByID(id)
	if err != nil {
		http.NotFound(w, r)
		return peer{}, "", false
	}
	config, err := s.decryptedPeerConfig(p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return peer{}, "", false
	}
	return p, config, true
}

func (s *server) togglePeer(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "CSRF token tidak valid", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	p, err := s.store.peerByID(id)
	if err != nil {
		http.Error(w, "Peer tidak ditemukan", http.StatusNotFound)
		return
	}
	if err := s.store.setPeerEnabled(id, !p.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.applyWireGuard(); err != nil {
		_ = s.store.setPeerEnabled(id, p.Enabled)
		_ = s.applyWireGuard()
		http.Error(w, "Status peer gagal diubah: "+err.Error(), http.StatusInternalServerError)
		return
	}
	state := "dinonaktifkan"
	if !p.Enabled {
		state = "diaktifkan"
	}
	s.store.audit("peer.toggle", p.Name+" "+state, clientIP(r))
	next := r.FormValue("next")
	if next != fmt.Sprintf("/peers/%d", id) {
		next = "/peers"
	}
	http.Redirect(w, r, next+"?notice=Peer+"+state, http.StatusSeeOther)
}

func (s *server) deletePeer(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "CSRF token tidak valid", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	old, err := s.store.peerByID(id)
	if err != nil {
		http.Error(w, "Peer tidak ditemukan", http.StatusNotFound)
		return
	}
	if err := s.store.deletePeer(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.applyWireGuard(); err != nil {
		_ = s.store.restorePeer(old)
		_ = s.applyWireGuard()
		http.Error(w, "Peer gagal dihapus: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.audit("peer.delete", old.Name+" "+old.IP, clientIP(r))
	http.Redirect(w, r, "/peers?notice=Peer+dihapus", http.StatusSeeOther)
}

func (s *server) servicesPage(w http.ResponseWriter, r *http.Request) {
	services, _ := s.store.listServices()
	s.render(w, "services.html", s.data(r, "Domain & layanan", nil, services, wgStatus{}))
}

func (s *server) createService(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "CSRF token tidak valid", http.StatusForbidden)
		return
	}
	host := strings.ToLower(strings.TrimSpace(r.FormValue("host")))
	target := strings.TrimSpace(r.FormValue("target"))
	if err := validateService(host, target, s.cfg.BaseDomain); err != nil {
		s.serviceError(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	svc, err := s.store.createService(host, target)
	if err != nil {
		s.serviceError(w, r, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.writeRoutingFiles(); err != nil {
		_ = s.store.deleteService(svc.ID)
		_ = s.writeRoutingFiles()
		s.serviceError(w, r, "Konfigurasi proxy ditolak: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.audit("service.create", svc.Host+" "+svc.Target, clientIP(r))
	http.Redirect(w, r, "/services?notice=Layanan+ditambahkan", http.StatusSeeOther)
}

func (s *server) toggleService(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "CSRF token tidak valid", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	svc, err := s.store.serviceByID(id)
	if err != nil {
		http.Error(w, "Layanan tidak ditemukan", http.StatusNotFound)
		return
	}
	if err := s.store.setServiceEnabled(id, !svc.Enabled); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.writeRoutingFiles(); err != nil {
		_ = s.store.setServiceEnabled(id, svc.Enabled)
		_ = s.writeRoutingFiles()
		http.Error(w, "Status domain gagal diubah: "+err.Error(), http.StatusInternalServerError)
		return
	}
	state := "dinonaktifkan"
	if !svc.Enabled {
		state = "diaktifkan"
	}
	s.store.audit("service.toggle", svc.Host+" "+state, clientIP(r))
	http.Redirect(w, r, "/services?notice=Domain+"+state, http.StatusSeeOther)
}

func (s *server) deleteService(w http.ResponseWriter, r *http.Request) {
	if !s.validCSRF(r) {
		http.Error(w, "CSRF token tidak valid", http.StatusForbidden)
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	old, err := s.store.serviceByID(id)
	if err != nil {
		http.Error(w, "Layanan tidak ditemukan", http.StatusNotFound)
		return
	}
	if err := s.store.deleteService(id); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := s.writeRoutingFiles(); err != nil {
		_ = s.store.restoreService(old)
		_ = s.writeRoutingFiles()
		http.Error(w, "Layanan gagal dihapus: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.store.audit("service.delete", old.Host+" "+old.Target, clientIP(r))
	http.Redirect(w, r, "/services?notice=Layanan+dihapus", http.StatusSeeOther)
}

func (s *server) peerError(w http.ResponseWriter, r *http.Request, message string, statusCode int) {
	peers, _ := s.store.listPeers()
	status, _ := s.wireGuardStatus(peers)
	data := s.data(r, "Peer", peers, nil, status)
	data.Error = message
	s.renderStatus(w, "peers.html", data, statusCode)
}

func (s *server) serviceError(w http.ResponseWriter, r *http.Request, message string, statusCode int) {
	services, _ := s.store.listServices()
	data := s.data(r, "Domain & layanan", nil, services, wgStatus{})
	data.Error = message
	s.renderStatus(w, "services.html", data, statusCode)
}

func (s *server) data(r *http.Request, title string, peers []peer, services []service, status wgStatus) viewData {
	sess, _ := s.currentSession(r)
	return viewData{
		Title: title, User: s.cfg.AdminUser, CSRF: sess.CSRF, Peers: peers, Services: services, WG: status,
		Notice: r.URL.Query().Get("notice"), PanelDomain: "panel." + s.cfg.BaseDomain,
		BaseDomain: s.cfg.BaseDomain, Endpoint: s.cfg.PublicEndpoint,
	}
}

func (s *server) render(w http.ResponseWriter, name string, data viewData) {
	s.renderStatus(w, name, data, http.StatusOK)
}

func (s *server) renderStatus(w http.ResponseWriter, name string, data viewData, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if err := s.tpl.ExecuteTemplate(w, name, data); err != nil {
		log.Printf("template %s: %v", name, err)
	}
}

func (s *server) auth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, ok := s.currentSession(r); !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		next(w, r)
	}
}

func (s *server) currentSession(r *http.Request) (session, bool) {
	cookie, err := r.Cookie("pwg_session")
	if err != nil {
		return session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[cookie.Value]
	if !ok || time.Now().After(sess.Expires) {
		delete(s.sessions, cookie.Value)
		return session{}, false
	}
	return sess, true
}

func (s *server) validCSRF(r *http.Request) bool {
	sess, ok := s.currentSession(r)
	return ok && r.FormValue("csrf") != "" && subtleEqual(sess.CSRF, r.FormValue("csrf"))
}

func subtleEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var diff byte
	for i := range a {
		diff |= a[i] ^ b[i]
	}
	return diff == 0
}

func (s *server) rateLimited(ip string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := time.Now().Add(-15 * time.Minute)
	valid := s.attempts[ip][:0]
	for _, attempt := range s.attempts[ip] {
		if attempt.After(cutoff) {
			valid = append(valid, attempt)
		}
	}
	s.attempts[ip] = valid
	return len(valid) >= 5
}

func (s *server) recordFailure(ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[ip] = append(s.attempts[ip], time.Now())
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	proxyIP := net.ParseIP(host)
	if proxyIP != nil && (proxyIP.IsLoopback() || proxyIP.Equal(net.ParseIP("10.77.0.1"))) {
		if realIP := net.ParseIP(r.Header.Get("X-Real-IP")); realIP != nil {
			return realIP.String()
		}
	}
	return host
}

func randomToken(size int) string {
	buf := make([]byte, size)
	if _, err := rand.Read(buf); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(buf)
}

func hashPassword(password string, salt []byte) string {
	hash := argon2.IDKey([]byte(password), salt, 3, 64*1024, 2, 32)
	return base64.RawStdEncoding.EncodeToString(hash)
}

func initial(value string) string {
	for _, r := range value {
		return strings.ToUpper(string(r))
	}
	return "?"
}

func humanBytes(n int64) string {
	units := []string{"B", "KB", "MB", "GB", "TB"}
	value := float64(n)
	unit := units[0]
	for i := 1; value >= 1024 && i < len(units); i++ {
		value /= 1024
		unit = units[i]
	}
	return fmt.Sprintf("%.1f %s", value, unit)
}

func timeAgo(t time.Time) string {
	if t.IsZero() {
		return "belum pernah"
	}
	d := time.Since(t)
	if d < time.Minute {
		return "baru saja"
	}
	if d < time.Hour {
		return fmt.Sprintf("%d menit lalu", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%d jam lalu", int(d.Hours()))
	}
	return fmt.Sprintf("%d hari lalu", int(d.Hours()/24))
}
