package main

import (
	"net/http"
	"net/http/httptest"
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

func TestBuildRoutingConfigs(t *testing.T) {
	proxy, hosts, err := buildRoutingConfigs(config{BaseDomain: "example.com"}, []service{
		{ID: 1, Host: "active.example.com", Target: "10.77.0.20:80", Enabled: true},
		{ID: 2, Host: "paused.example.com", Target: "10.77.0.21:80", Enabled: false},
	})
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
	if got := cfg.HTTP.Middlewares["panel-auth"].ForwardAuth; got == nil || got.Address != "http://10.77.0.1:8080/__privatewg/auth" || !got.PreserveLocationHeader {
		t.Fatalf("panel auth = %#v", got)
	}
	active := cfg.HTTP.Routers["service-1"]
	if active.Service != "service-1" || strings.Join(active.Middlewares, ",") != "service-errors,vpn-only,retry-upstream" {
		t.Fatalf("active router = %#v", active)
	}
	if got := cfg.HTTP.Services["service-1"].LoadBalancer.Servers[0].URL; got != "http://10.77.0.20:80" {
		t.Fatalf("active upstream = %q", got)
	}
	allowlist := cfg.HTTP.Middlewares["vpn-only"].IPAllowList
	if len(allowlist.SourceRange) != 1 || allowlist.SourceRange[0] != "10.77.0.0/24" || allowlist.RejectStatusCode != 418 {
		t.Fatalf("VPN allowlist = %#v", allowlist)
	}
	errors := cfg.HTTP.Middlewares["service-errors"].Errors
	if strings.Join(errors.Status, ",") != "418,502,504" || errors.StatusRewrites["418"] != http.StatusForbidden {
		t.Fatalf("error middleware = %#v", errors)
	}
	retry := cfg.HTTP.Middlewares["retry-upstream"].Retry
	if retry.Attempts != 16 || retry.InitialInterval != "500ms" || retry.Timeout != "8s" || strings.Join(retry.Status, ",") != "502,504" {
		t.Fatalf("retry = %#v", retry)
	}
	transport := cfg.HTTP.ServersTransports["privatewg-upstream"]
	if transport.MaxIdleConnsPerHost != 5 || transport.ForwardingTimeouts.DialTimeout != "30s" || transport.ForwardingTimeouts.ResponseHeaderTimeout != "30s" || transport.ForwardingTimeouts.IdleConnTimeout != "30s" {
		t.Fatalf("transport = %#v", transport)
	}
	paused := cfg.HTTP.Routers["service-2"]
	if paused.Service != "privatewg-errors" || strings.Join(paused.Middlewares, ",") != "paused-route" {
		t.Fatalf("paused router = %#v", paused)
	}
	if _, exists := cfg.HTTP.Services["service-2"]; exists {
		t.Fatal("paused service must not proxy to its upstream")
	}
	if !strings.Contains(string(hosts), "10.77.0.1 paused.example.com") {
		t.Fatal("paused service must remain resolvable for its error page")
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
	s.traefikAuth(unauthorized, httptest.NewRequest(http.MethodGet, "/__privatewg/auth", nil))
	if unauthorized.Code != http.StatusSeeOther || unauthorized.Header().Get("Location") != "/login" {
		t.Fatalf("unauthorized auth response = %d, location %q", unauthorized.Code, unauthorized.Header().Get("Location"))
	}

	s.sessions["valid"] = session{Expires: time.Now().Add(time.Hour)}
	authorized := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/__privatewg/auth", nil)
	req.AddCookie(&http.Cookie{Name: "pwg_session", Value: "valid"})
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
		{http.StatusForbidden, "VPN diperlukan"},
		{http.StatusBadGateway, "Aplikasi tidak terjangkau"},
		{http.StatusServiceUnavailable, "Rute sedang dijeda"},
	} {
		req := httptest.NewRequest(http.MethodGet, "/__privatewg/errors/"+strconv.Itoa(test.status), nil)
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
