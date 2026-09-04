package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestValidateService(t *testing.T) {
	tests := []struct {
		host, target string
		valid        bool
	}{
		{"app.example.com", "127.0.0.1:8081", true},
		{"remote.example.com", "10.77.0.20:80", true},
		{"app.external.test", "10.77.0.20:80", true},
		{"panel.example.com", "10.77.0.20:80", false},
		{"app.example.com", "8.8.8.8:80", false},
		{"app.example.com", "10.77.0.20:99999", false},
		{"app.example.com", "localhost:8080/path", false},
	}
	for _, test := range tests {
		err := validateService(test.host, test.target, "example.com")
		if (err == nil) != test.valid {
			t.Errorf("validateService(%q, %q) error=%v, valid=%v", test.host, test.target, err, test.valid)
		}
	}
}

func TestValidatePublicTarget(t *testing.T) {
	for _, test := range []struct {
		target, listen string
		valid          bool
	}{
		{"10.77.0.20:80", "10.77.0.1:8080", true},
		{"127.0.0.1:8081", "10.77.0.1:8080", true},
		{"10.77.0.1:8080", "10.77.0.1:8080", false},
		{"10.77.0.1:08080", "10.77.0.1:8080", false},
		{"[::ffff:10.77.0.1]:8080", "10.77.0.1:8080", false},
		{"127.0.0.1:8080", ":8080", false},
	} {
		err := validatePublicTarget(test.target, test.listen)
		if (err == nil) != test.valid {
			t.Errorf("validatePublicTarget(%q, %q) error=%v, valid=%v", test.target, test.listen, err, test.valid)
		}
	}
}

func TestBuildRoutingConfigs(t *testing.T) {
	proxy, hosts, err := buildRoutingConfigs(config{BaseDomain: "example.com"}, []service{
		{ID: 1, Host: "active.example.com", Target: "10.77.0.20:80", Enabled: true},
		{ID: 2, Host: "paused.example.com", Target: "10.77.0.21:80", Enabled: false},
		{ID: 3, Host: "denied.example.com", Target: "10.77.0.22:80", Enabled: true},
		{ID: 4, Host: "public.example.com", Target: "10.77.0.23:80", Enabled: true, Public: true},
		{ID: 5, Host: "public-paused.example.com", Target: "10.77.0.24:80", Enabled: false, Public: true},
	}, map[int64][]string{1: {"10.77.0.2/32", "10.77.0.4/32"}})
	if err != nil {
		t.Fatal(err)
	}
	var cfg traefikConfig
	if err := yaml.Unmarshal(proxy, &cfg); err != nil {
		t.Fatalf("invalid Traefik YAML: %v", err)
	}
	if got := cfg.HTTP.Routers["panel"].Rule; got != "Host(`panel.example.com`)" {
		t.Fatalf("panel rule = %q", got)
	}
	dashboard := cfg.HTTP.Routers["traefik-dashboard"]
	if dashboard.Service != "api@internal" || dashboard.Rule != "Host(`panel.example.com`) && PathPrefix(`/traefik`)" || strings.Join(dashboard.Middlewares, ",") != "panel-auth" || dashboard.Priority != 100 {
		t.Fatalf("dashboard router = %#v", dashboard)
	}
	if got := cfg.HTTP.Middlewares["panel-auth"].ForwardAuth; got == nil || got.Address != "http://10.77.0.1:8080/__frontlane/auth" || !got.PreserveLocationHeader {
		t.Fatalf("panel auth = %#v", got)
	}
	active := cfg.HTTP.Routers["service-1"]
	if active.Service != "service-1" || strings.Join(active.Middlewares, ",") != "service-errors,service-1-access,retry-upstream" {
		t.Fatalf("active router = %#v", active)
	}
	if got := cfg.HTTP.Services["service-1"].LoadBalancer.Servers[0].URL; got != "http://10.77.0.20:80" {
		t.Fatalf("active upstream = %q", got)
	}
	allowlist := cfg.HTTP.Middlewares["service-1-access"].IPAllowList
	if strings.Join(allowlist.SourceRange, ",") != "10.77.0.2/32,10.77.0.4/32" || allowlist.RejectStatusCode != 418 {
		t.Fatalf("role allowlist = %#v", allowlist)
	}
	errors := cfg.HTTP.Middlewares["service-errors"].Errors
	if strings.Join(errors.Status, ",") != "418,502,504" || errors.StatusRewrites["418"] != http.StatusForbidden {
		t.Fatalf("error middleware = %#v", errors)
	}
	retry := cfg.HTTP.Middlewares["retry-upstream"].Retry
	if retry.Attempts != 16 || retry.InitialInterval != "500ms" || retry.Timeout != "8s" || strings.Join(retry.Status, ",") != "502,504" {
		t.Fatalf("retry = %#v", retry)
	}
	transport := cfg.HTTP.ServersTransports["frontlane-upstream"]
	if transport.MaxIdleConnsPerHost != 5 || transport.ForwardingTimeouts.DialTimeout != "30s" || transport.ForwardingTimeouts.ResponseHeaderTimeout != "30s" || transport.ForwardingTimeouts.IdleConnTimeout != "30s" {
		t.Fatalf("transport = %#v", transport)
	}
	paused := cfg.HTTP.Routers["service-2"]
	if paused.Service != "frontlane-errors" || strings.Join(paused.Middlewares, ",") != "paused-route" {
		t.Fatalf("paused router = %#v", paused)
	}
	if _, exists := cfg.HTTP.Services["service-2"]; exists {
		t.Fatal("paused service must not proxy to its upstream")
	}
	denied := cfg.HTTP.Routers["service-3"]
	if denied.Service != "frontlane-errors" || strings.Join(denied.Middlewares, ",") != "denied-route" {
		t.Fatalf("denied router = %#v", denied)
	}
	if _, exists := cfg.HTTP.Services["service-3"]; exists {
		t.Fatal("unauthorized service must not proxy to its upstream")
	}
	if cfg.HTTP.Middlewares["denied-route"].ReplacePath.Path != "/__frontlane/errors/403" {
		t.Fatal("unauthorized service must route to 403")
	}
	public := cfg.HTTP.Routers["service-4"]
	if public.Service != "service-4" || strings.Join(public.Middlewares, ",") != "public-service-errors,retry-upstream" {
		t.Fatalf("public router = %#v", public)
	}
	if _, exists := cfg.HTTP.Middlewares["service-4-access"]; exists {
		t.Fatal("public service must not have an IP allowlist")
	}
	publicErrors := cfg.HTTP.Middlewares["public-service-errors"].Errors
	if strings.Join(publicErrors.Status, ",") != "502,504" || publicErrors.StatusRewrites != nil {
		t.Fatalf("public error middleware = %#v", publicErrors)
	}
	if strings.Contains(string(proxy), "public-service-errors:\n      errors:\n        statusRewrites:") {
		t.Fatal("public error middleware must omit empty statusRewrites")
	}
	publicPaused := cfg.HTTP.Routers["service-5"]
	if publicPaused.Service != "frontlane-errors" || strings.Join(publicPaused.Middlewares, ",") != "paused-route" {
		t.Fatalf("paused public router = %#v", publicPaused)
	}
	if !strings.Contains(string(hosts), "10.77.0.1 paused.example.com") {
		t.Fatal("paused service must remain resolvable for its error page")
	}
}

func TestSetServiceAccess(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "frontlane.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err := st.createService("app.example.com", "10.77.0.20:80", false)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		cfg: config{
			Listen:             "10.77.0.1:8080",
			BaseDomain:         "example.com",
			TraefikDynamicFile: filepath.Join(dir, "dynamic.yml"),
			CoreDNSHosts:       filepath.Join(dir, "domains.hosts"),
		},
		store: st, sessions: map[string]session{"valid": {CSRF: "token", Expires: time.Now().Add(time.Hour)}},
	}
	form := url.Values{"csrf": {"token"}, "access": {"public"}}
	req := httptest.NewRequest(http.MethodPost, "/services/1/access", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", strconv.FormatInt(svc.ID, 10))
	req.AddCookie(&http.Cookie{Name: "frontlane_session", Value: "valid"})
	response := httptest.NewRecorder()
	s.setServiceAccess(response, req)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("access response = %d: %s", response.Code, response.Body.String())
	}
	updated, err := st.serviceByID(svc.ID)
	if err != nil || !updated.Public {
		t.Fatalf("public state = %#v, error = %v", updated, err)
	}
	proxy, err := os.ReadFile(s.cfg.TraefikDynamicFile)
	if err != nil || !strings.Contains(string(proxy), "public-service-errors") {
		t.Fatalf("public routing not written: %v", err)
	}
}

func TestUpdateService(t *testing.T) {
	dir := t.TempDir()
	st, err := openStore(filepath.Join(dir, "frontlane.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	svc, err := st.createService("old.example.com", "10.77.0.20:80", false)
	if err != nil {
		t.Fatal(err)
	}
	s := &server{
		cfg: config{
			Listen:             "10.77.0.1:8080",
			BaseDomain:         "example.com",
			TraefikDynamicFile: filepath.Join(dir, "dynamic.yml"),
			CoreDNSHosts:       filepath.Join(dir, "domains.hosts"),
		},
		store: st, sessions: map[string]session{"valid": {CSRF: "token", Expires: time.Now().Add(time.Hour)}},
	}
	form := url.Values{"csrf": {"token"}, "host": {"new.example.com"}, "target": {"10.77.0.21:8080"}}
	req := httptest.NewRequest(http.MethodPost, "/services/1", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetPathValue("id", strconv.FormatInt(svc.ID, 10))
	req.AddCookie(&http.Cookie{Name: "frontlane_session", Value: "valid"})
	response := httptest.NewRecorder()
	s.updateService(response, req)
	if response.Code != http.StatusSeeOther {
		t.Fatalf("update response = %d: %s", response.Code, response.Body.String())
	}
	updated, err := st.serviceByID(svc.ID)
	if err != nil || updated.Host != "new.example.com" || updated.Target != "10.77.0.21:8080" {
		t.Fatalf("updated service = %#v, error = %v", updated, err)
	}
}

func TestClientIPTrustsOnlyLocalProxy(t *testing.T) {
	trusted := httptest.NewRequest(http.MethodGet, "/", nil)
	trusted.RemoteAddr = "127.0.0.1:1234"
	trusted.Header.Set("X-Forwarded-For", "10.77.0.20, 127.0.0.1")
	if got := clientIP(trusted); got != "10.77.0.20" {
		t.Fatalf("trusted proxy client IP = %q", got)
	}

	untrusted := httptest.NewRequest(http.MethodGet, "/", nil)
	untrusted.RemoteAddr = "203.0.113.20:1234"
	untrusted.Header.Set("X-Forwarded-For", "10.77.0.20")
	if got := clientIP(untrusted); got != "203.0.113.20" {
		t.Fatalf("untrusted proxy client IP = %q", got)
	}
}

func TestTraefikAuth(t *testing.T) {
	s := &server{sessions: map[string]session{}}

	unauthorized := httptest.NewRecorder()
	s.traefikAuth(unauthorized, httptest.NewRequest(http.MethodGet, "/__frontlane/auth", nil))
	if unauthorized.Code != http.StatusSeeOther || unauthorized.Header().Get("Location") != "/login" {
		t.Fatalf("unauthorized auth response = %d, location %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}

	s.sessions["valid"] = session{Expires: time.Now().Add(time.Hour)}
	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/__frontlane/auth", nil)
	req.AddCookie(&http.Cookie{Name: "frontlane_session", Value: "valid"})
	s.traefikAuth(authorized, req)
	if authorized.Code != http.StatusOK {
		t.Fatalf("authorized auth response = %d", authorized.Code)
	}
}

func TestRouteErrorPage(t *testing.T) {
	for _, test := range []struct {
		status int
		want   string
	}{
		{http.StatusForbidden, "Access denied"},
		{http.StatusBadGateway, "Application unreachable"},
		{http.StatusServiceUnavailable, "Route paused"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/__frontlane/errors/"+strconv.Itoa(test.status), nil)
		req.SetPathValue("status", strconv.Itoa(test.status))
		res := httptest.NewRecorder()
		routeErrorPage(res, req)
		if res.Code != test.status || !strings.Contains(res.Body.String(), test.want) {
			t.Errorf("status %d: code=%d body=%q", test.status, res.Code, res.Body.String())
		}
		if !strings.Contains(res.Header().Get("Content-Security-Policy"), "style-src 'unsafe-inline'") || strings.Contains(res.Body.String(), "onclick=") {
			t.Errorf("status %d: unsafe error page policy", test.status)
		}
	}
}
