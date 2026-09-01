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
	var caddy strings.Builder
	fmt.Fprintf(&caddy, "{\n    email %s\n    admin 127.0.0.1:2019\n}\n\n", s.cfg.ACMEEmail)
	fmt.Fprintf(&caddy, "panel.%s {\n    reverse_proxy 10.77.0.1:8080 {\n        header_up X-Real-IP {remote_host}\n    }\n    tls {\n        issuer acme {\n            disable_tlsalpn_challenge\n        }\n    }\n}\n", s.cfg.BaseDomain)
	for _, svc := range services {
		if svc.Enabled {
			fmt.Fprintf(&caddy, "\n%s {\n    @vpn remote_ip 10.77.0.0/24\n    handle @vpn {\n        reverse_proxy %s\n    }\n    respond 403\n    tls {\n        issuer acme {\n            disable_tlsalpn_challenge\n        }\n    }\n}\n", svc.Host, svc.Target)
		}
	}
	var hosts strings.Builder
	fmt.Fprintf(&hosts, "10.77.0.1 panel.%s\n", s.cfg.BaseDomain)
	for _, svc := range services {
		if svc.Enabled {
			fmt.Fprintf(&hosts, "10.77.0.1 %s\n", svc.Host)
		}
	}
	configBytes := []byte(caddy.String())
	if err := reloadCaddy(configBytes); err != nil {
		return err
	}
	if err := atomicWrite(s.cfg.CaddyFile, configBytes, 0644); err != nil {
		return err
	}
	return atomicWrite(s.cfg.CoreDNSHosts, []byte(hosts.String()), 0644)
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
