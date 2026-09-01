package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

func validateService(host, target, baseDomain string) error {
	if len(host) > 253 || !hostnamePattern.MatchString(host) {
		return errors.New("domain tidak valid")
	}
	if host == "panel."+baseDomain {
		return errors.New("domain panel dicadangkan untuk PrivateWG")
	}
	u, err := url.Parse("http://" + target)
	if err != nil || u.Host != target || u.Path != "" || u.User != nil {
		return errors.New("target harus berbentuk host:port")
	}
	hostPart, port, err := net.SplitHostPort(target)
	if err != nil || hostPart == "" || port == "" {
		return errors.New("target harus berbentuk host:port")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("port target harus 1-65535")
	}
	if ip := net.ParseIP(hostPart); ip != nil {
		_, vpn, _ := net.ParseCIDR("10.77.0.0/24")
		if !vpn.Contains(ip) && !ip.IsLoopback() {
			return errors.New("target IP hanya boleh loopback atau subnet 10.77.0.0/24")
		}
	} else if hostPart != "localhost" {
		return errors.New("hostname target hanya boleh localhost; gunakan IP WireGuard untuk VPS lain")
	}
	return nil
}

func (s *server) writeRoutingFiles() error {
	services, err := s.store.listServices()
	if err != nil {
		return err
	}
	caddy, hosts := buildRoutingConfigs(s.cfg, services)
	if err := reloadCaddy(caddy); err != nil {
		return err
	}
	if err := atomicWrite(s.cfg.CaddyFile, caddy, 0644); err != nil {
		return err
	}
	return atomicWrite(s.cfg.CoreDNSHosts, hosts, 0644)
}

func buildRoutingConfigs(cfg config, services []service) ([]byte, []byte) {
	var caddy strings.Builder
	fmt.Fprintf(&caddy, "{\n    email %s\n    admin 127.0.0.1:2019\n}\n\n", cfg.ACMEEmail)
	fmt.Fprintf(&caddy, "panel.%s {\n    reverse_proxy 10.77.0.1:8080 {\n        header_up X-Real-IP {remote_host}\n    }\n    tls {\n        issuer acme {\n            disable_tlsalpn_challenge\n        }\n    }\n}\n", cfg.BaseDomain)
	for _, svc := range services {
		writeServiceSite(&caddy, svc)
	}

	var hosts strings.Builder
	fmt.Fprintf(&hosts, "10.77.0.1 panel.%s\n", cfg.BaseDomain)
	for _, svc := range services {
		fmt.Fprintf(&hosts, "10.77.0.1 %s\n", svc.Host)
	}
	return []byte(caddy.String()), []byte(hosts.String())
}

func writeServiceSite(caddy *strings.Builder, svc service) {
	fmt.Fprintf(caddy, "\n%s {\n", svc.Host)
	if svc.Enabled {
		fmt.Fprintf(caddy, "    @vpn remote_ip 10.77.0.0/24\n    handle @vpn {\n        reverse_proxy %s {\n            lb_try_duration 8s\n            lb_try_interval 500ms\n            transport http {\n                dial_timeout 30s\n                read_timeout 30s\n                keepalive 30s\n                keepalive_idle_conns 5\n                }\n        }\n    }\n", svc.Target)
		writeErrorPage(caddy, "handle", "VPN diperlukan", "PRIVATE NETWORK", "Hubungkan perangkat ke WireGuard, lalu muat ulang halaman ini.", 403)
		fmt.Fprint(caddy, "    handle_errors {\n")
		writeErrorPage(caddy, "", "Aplikasi tidak terjangkau", "UPSTREAM OFFLINE", "Tunnel aktif, tetapi server aplikasi belum merespons. Periksa peer atau layanan di VPS tujuan.", 502)
		fmt.Fprint(caddy, "    }\n")
	} else {
		writeErrorPage(caddy, "handle", "Rute sedang dijeda", "ROUTE PAUSED", "Domain ini dinonaktifkan sementara oleh administrator jaringan.", 503)
	}
	fmt.Fprint(caddy, "    tls {\n        issuer acme {\n            disable_tlsalpn_challenge\n        }\n    }\n}\n")
}

func writeErrorPage(caddy *strings.Builder, block, title, label, message string, status int) {
	if block != "" {
		fmt.Fprintf(caddy, "    %s {\n", block)
	}
	indent := "        "
	fmt.Fprintf(caddy, "%sheader Content-Type \"text/html; charset=utf-8\"\n%sheader Cache-Control \"no-store\"\n%srespond <<HTML\n", indent, indent, indent)
	fmt.Fprintf(caddy, "%s<!doctype html><html lang=\"id\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"color-scheme\" content=\"light\"><title>%s - PrivateWG</title><style>:root{color:#163044;background:#eef5f7;font-family:ui-sans-serif,system-ui,sans-serif}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 15%% 12%%,#d5f1ec 0,transparent 28rem),radial-gradient(circle at 85%% 90%%,#dbe8f5 0,transparent 30rem),#eef5f7}.card{width:min(620px,100%%);padding:48px;background:#ffffffea;border:1px solid #cfdee5;border-radius:26px;box-shadow:0 28px 80px #17384c1a}.signal{display:flex;gap:4px;align-items:end;height:25px;margin-bottom:32px}.signal i{display:block;width:5px;background:#12a99b;border-radius:4px}.signal i:nth-child(1){height:9px}.signal i:nth-child(2){height:16px}.signal i:nth-child(3){height:24px;opacity:.3}.label{color:#07877e;font:700 11px ui-monospace,monospace;letter-spacing:.16em}h1{margin:12px 0 14px;color:#0b2942;font-size:clamp(34px,7vw,56px);line-height:1;letter-spacing:-.045em}p{margin:0;color:#627b8c;font-size:16px;line-height:1.7}.meta{display:flex;justify-content:space-between;gap:12px;margin-top:34px;padding-top:18px;border-top:1px solid #dce7ee;color:#77909f;font:11px ui-monospace,monospace}button{margin-top:27px;padding:12px 17px;color:white;background:#07877e;border:0;border-radius:11px;font:700 13px inherit;cursor:pointer}button:hover{background:#096f69}@media(max-width:520px){.card{padding:32px 25px}.meta{display:grid}}</style></head><body><main class=\"card\"><div class=\"signal\" aria-hidden=\"true\"><i></i><i></i><i></i></div><span class=\"label\">%s - %d</span><h1>%s</h1><p>%s</p><button onclick=\"location.reload()\">Coba lagi</button><div class=\"meta\"><span>PrivateWG network edge</span><span>HTTP %d</span></div></main></body></html>\n", indent, title, label, status, title, message, status)
	fmt.Fprintf(caddy, "%sHTML %d\n", indent, status)
	if block != "" {
		fmt.Fprint(caddy, "    }\n")
	}
}

func reloadCaddy(config []byte) error {
	req, err := http.NewRequest(http.MethodPost, "http://127.0.0.1:2019/load", bytes.NewReader(config))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "text/caddyfile")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		// Caddy starts after PrivateWG on bootstrap and reads the generated file.
		if errors.Is(err, syscall.ECONNREFUSED) || strings.Contains(err.Error(), "connection refused") {
			return nil
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Caddy menolak konfigurasi: %s", strings.TrimSpace(string(body)))
	}
	return nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".privatewg-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
