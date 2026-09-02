package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

var hostnamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

type traefikConfig struct {
	HTTP traefikHTTP `yaml:"http"`
}

type traefikHTTP struct {
	Routers           map[string]traefikRouter           `yaml:"routers"`
	Middlewares       map[string]traefikMiddleware       `yaml:"middlewares"`
	Services          map[string]traefikService          `yaml:"services"`
	ServersTransports map[string]traefikServersTransport `yaml:"serversTransports"`
}

type traefikRouter struct {
	EntryPoints []string   `yaml:"entryPoints"`
	Rule        string     `yaml:"rule"`
	Service     string     `yaml:"service"`
	Middlewares []string   `yaml:"middlewares,omitempty"`
	TLS         traefikTLS `yaml:"tls"`
}

type traefikTLS struct {
	CertResolver string `yaml:"certResolver"`
}

type traefikMiddleware struct {
	IPAllowList *traefikIPAllowList `yaml:"ipAllowList,omitempty"`
	Retry       *traefikRetry       `yaml:"retry,omitempty"`
	Errors      *traefikErrors      `yaml:"errors,omitempty"`
	ReplacePath *traefikReplacePath `yaml:"replacePath,omitempty"`
}

type traefikIPAllowList struct {
	SourceRange      []string `yaml:"sourceRange"`
	RejectStatusCode int      `yaml:"rejectStatusCode"`
}

type traefikRetry struct {
	Attempts        int      `yaml:"attempts"`
	InitialInterval string   `yaml:"initialInterval"`
	Timeout         string   `yaml:"timeout"`
	Status          []string `yaml:"status"`
}

type traefikErrors struct {
	Status              []string       `yaml:"status"`
	StatusRewrites      map[string]int `yaml:"statusRewrites"`
	Service             string         `yaml:"service"`
	Query               string         `yaml:"query"`
	ErrorRequestHeaders []string       `yaml:"errorRequestHeaders"`
}

type traefikReplacePath struct {
	Path string `yaml:"path"`
}

type traefikService struct {
	LoadBalancer traefikLoadBalancer `yaml:"loadBalancer"`
}

type traefikLoadBalancer struct {
	Servers          []traefikServer `yaml:"servers"`
	ServersTransport string          `yaml:"serversTransport,omitempty"`
	PassHostHeader   *bool           `yaml:"passHostHeader,omitempty"`
}

type traefikServer struct {
	URL string `yaml:"url"`
}

type traefikServersTransport struct {
	MaxIdleConnsPerHost int                       `yaml:"maxIdleConnsPerHost"`
	ForwardingTimeouts  traefikForwardingTimeouts `yaml:"forwardingTimeouts"`
}

type traefikForwardingTimeouts struct {
	DialTimeout           string `yaml:"dialTimeout"`
	ResponseHeaderTimeout string `yaml:"responseHeaderTimeout"`
	IdleConnTimeout       string `yaml:"idleConnTimeout"`
}

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
	proxy, hosts, err := buildRoutingConfigs(s.cfg, services)
	if err != nil {
		return err
	}
	if err := atomicWrite(s.cfg.TraefikDynamicFile, proxy, 0644); err != nil {
		return err
	}
	return atomicWrite(s.cfg.CoreDNSHosts, hosts, 0644)
}

func buildRoutingConfigs(cfg config, services []service) ([]byte, []byte, error) {
	falseValue := false
	httpConfig := traefikHTTP{
		Routers: map[string]traefikRouter{
			"panel": {
				EntryPoints: []string{"websecure"},
				Rule:        fmt.Sprintf("Host(`panel.%s`)", cfg.BaseDomain),
				Service:     "privatewg-panel",
				TLS:         traefikTLS{CertResolver: "letsencrypt"},
			},
		},
		Middlewares: map[string]traefikMiddleware{
			"vpn-only": {
				IPAllowList: &traefikIPAllowList{SourceRange: []string{"10.77.0.0/24"}, RejectStatusCode: 418},
			},
			"retry-upstream": {
				Retry: &traefikRetry{Attempts: 16, InitialInterval: "500ms", Timeout: "8s", Status: []string{"502", "504"}},
			},
			"service-errors": {
				Errors: &traefikErrors{
					Status:              []string{"418", "502", "504"},
					StatusRewrites:      map[string]int{"418": http.StatusForbidden},
					Service:             "privatewg-errors",
					Query:               "/__privatewg/errors/{status}",
					ErrorRequestHeaders: []string{},
				},
			},
			"paused-route": {
				ReplacePath: &traefikReplacePath{Path: "/__privatewg/errors/503"},
			},
		},
		Services: map[string]traefikService{
			"privatewg-panel": {
				LoadBalancer: traefikLoadBalancer{Servers: []traefikServer{{URL: "http://10.77.0.1:8080"}}},
			},
			"privatewg-errors": {
				LoadBalancer: traefikLoadBalancer{
					Servers:        []traefikServer{{URL: "http://10.77.0.1:8080"}},
					PassHostHeader: &falseValue,
				},
			},
		},
		ServersTransports: map[string]traefikServersTransport{
			"privatewg-upstream": {
				MaxIdleConnsPerHost: 5,
				ForwardingTimeouts: traefikForwardingTimeouts{
					DialTimeout:           "30s",
					ResponseHeaderTimeout: "30s",
					IdleConnTimeout:       "30s",
				},
			},
		},
	}

	for _, svc := range services {
		name := "service-" + strconv.FormatInt(svc.ID, 10)
		router := traefikRouter{
			EntryPoints: []string{"websecure"},
			Rule:        fmt.Sprintf("Host(`%s`)", svc.Host),
			TLS:         traefikTLS{CertResolver: "letsencrypt"},
		}
		if svc.Enabled {
			router.Service = name
			router.Middlewares = []string{"service-errors", "vpn-only", "retry-upstream"}
			httpConfig.Services[name] = traefikService{
				LoadBalancer: traefikLoadBalancer{
					Servers:          []traefikServer{{URL: "http://" + svc.Target}},
					ServersTransport: "privatewg-upstream",
				},
			}
		} else {
			router.Service = "privatewg-errors"
			router.Middlewares = []string{"paused-route"}
		}
		httpConfig.Routers[name] = router
	}

	proxy, err := yaml.Marshal(traefikConfig{HTTP: httpConfig})
	if err != nil {
		return nil, nil, err
	}
	proxy = append(proxy, '\n')

	var hosts strings.Builder
	fmt.Fprintf(&hosts, "10.77.0.1 panel.%s\n", cfg.BaseDomain)
	for _, svc := range services {
		fmt.Fprintf(&hosts, "10.77.0.1 %s\n", svc.Host)
	}
	return proxy, []byte(hosts.String()), nil
}

func routeErrorPage(w http.ResponseWriter, r *http.Request) {
	status, err := strconv.Atoi(r.PathValue("status"))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	title := "Aplikasi tidak terjangkau"
	label := "UPSTREAM OFFLINE"
	message := "Tunnel aktif, tetapi server aplikasi belum merespons. Periksa peer atau layanan di VPS tujuan."
	switch status {
	case http.StatusForbidden:
		title = "VPN diperlukan"
		label = "PRIVATE NETWORK"
		message = "Hubungkan perangkat ke WireGuard, lalu muat ulang halaman ini."
	case http.StatusServiceUnavailable:
		title = "Rute sedang dijeda"
		label = "ROUTE PAUSED"
		message = "Domain ini dinonaktifkan sementara oleh administrator jaringan."
	case http.StatusBadGateway, http.StatusGatewayTimeout:
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><title>%s - PrivateWG</title>
<style>:root{color:#163044;background:#eef5f7;font-family:ui-sans-serif,system-ui,sans-serif}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 15%% 12%%,#d5f1ec 0,transparent 28rem),radial-gradient(circle at 85%% 90%%,#dbe8f5 0,transparent 30rem),#eef5f7}.card{width:min(620px,100%%);padding:48px;background:#ffffffea;border:1px solid #cfdee5;border-radius:26px;box-shadow:0 28px 80px #17384c1a}.signal{display:flex;gap:4px;align-items:end;height:25px;margin-bottom:32px}.signal i{display:block;width:5px;background:#12a99b;border-radius:4px}.signal i:nth-child(1){height:9px}.signal i:nth-child(2){height:16px}.signal i:nth-child(3){height:24px;opacity:.3}.label{color:#07877e;font:700 11px ui-monospace,monospace;letter-spacing:.16em}h1{margin:12px 0 14px;color:#0b2942;font-size:clamp(34px,7vw,56px);line-height:1;letter-spacing:-.045em}p{margin:0;color:#627b8c;font-size:16px;line-height:1.7}.meta{display:flex;justify-content:space-between;gap:12px;margin-top:34px;padding-top:18px;border-top:1px solid #dce7ee;color:#77909f;font:11px ui-monospace,monospace}@media(max-width:520px){.card{padding:32px 25px}.meta{display:grid}}</style></head>
<body><main class="card"><div class="signal" aria-hidden="true"><i></i><i></i><i></i></div><span class="label">%s - %d</span><h1>%s</h1><p>%s</p><div class="meta"><span>PrivateWG network edge</span><span>HTTP %d</span></div></main></body></html>`, title, label, status, title, message, status)
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
