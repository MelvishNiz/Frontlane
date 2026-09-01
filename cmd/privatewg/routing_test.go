package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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

func TestBuildRoutingConfigsIncludesErrorPages(t *testing.T) {
	caddy, hosts := buildRoutingConfigs(config{BaseDomain: "example.com", ACMEEmail: "admin@example.com"}, []service{
		{Host: "active.example.com", Target: "10.77.0.20:80", Enabled: true},
		{Host: "paused.example.com", Target: "10.77.0.21:80", Enabled: false},
	})
	configText := string(caddy)
	for _, want := range []string{"VPN diperlukan", "Aplikasi tidak terjangkau", "Rute sedang dijeda", "active.example.com", "paused.example.com"} {
		if !strings.Contains(configText, want) {
			t.Errorf("Caddy config missing %q", want)
		}
	}
	if strings.Contains(configText, "reverse_proxy 10.77.0.21:80") {
		t.Fatal("paused service must not proxy to its upstream")
	}
	if !strings.Contains(string(hosts), "10.77.0.1 paused.example.com") {
		t.Fatal("paused service must remain resolvable for its error page")
	}

	if _, err := exec.LookPath("caddy"); err != nil {
		t.Skip("caddy unavailable")
	}
	path := filepath.Join(t.TempDir(), "Caddyfile")
	if err := os.WriteFile(path, caddy, 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("caddy", "validate", "--config", path, "--adapter", "caddyfile").CombinedOutput(); err != nil {
		t.Fatalf("invalid generated Caddyfile: %v\n%s", err, output)
	}
}
