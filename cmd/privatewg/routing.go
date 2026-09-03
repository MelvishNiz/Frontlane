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
	Priority    int        `yaml:"priority,omitempty"`
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
	ForwardAuth *traefikForwardAuth `yaml:"forwardAuth,omitempty"`
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
	StatusRewrites      map[string]int `yaml:"statusRewrites,omitempty"`
	Service             string         `yaml:"service"`
	Query               string         `yaml:"query"`
	ErrorRequestHeaders []string       `yaml:"errorRequestHeaders"`
}

type traefikReplacePath struct {
	Path string `yaml:"path"`
}

type traefikForwardAuth struct {
	Address                string `yaml:"address"`
	TrustForwardHeader     bool   `yaml:"trustForwardHeader"`
	PreserveLocationHeader bool   `yaml:"preserveLocationHeader"`
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
		return errors.New("invalid domain")
	}
	if host == "panel."+baseDomain {
		return errors.New("the panel domain is reserved for Frontlane")
	}
	u, err := url.Parse("http://" + target)
	if err != nil || u.Host != target || u.Path != "" || u.User != nil {
		return errors.New("target must use host:port format")
	}
	hostPart, port, err := net.SplitHostPort(target)
	if err != nil || hostPart == "" || port == "" {
		return errors.New("target must use host:port format")
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("target port must be between 1 and 65535")
	}
	if ip := net.ParseIP(hostPart); ip != nil {
		_, vpn, _ := net.ParseCIDR("10.77.0.0/24")
		if !vpn.Contains(ip) && !ip.IsLoopback() {
			return errors.New("target IP must be loopback or within 10.77.0.0/24")
		}
	} else if hostPart != "localhost" {
		return errors.New("target hostname must be localhost; use the WireGuard IP for another server")
	}
	return nil
}

func validatePublicTarget(target, listen string) error {
	targetHost, targetPort, targetErr := net.SplitHostPort(target)
	listenHost, listenPort, listenErr := net.SplitHostPort(listen)
	targetPortNumber, targetPortErr := strconv.Atoi(targetPort)
	listenPortNumber, listenPortErr := strconv.Atoi(listenPort)
	if targetErr != nil || listenErr != nil || targetPortErr != nil || listenPortErr != nil || targetPortNumber != listenPortNumber {
		return nil
	}
	listenIP := net.ParseIP(listenHost)
	targetIP := net.ParseIP(targetHost)
	sameIP := listenIP != nil && targetIP != nil && listenIP.Equal(targetIP)
	sameLoopback := (targetHost == "localhost" && listenIP != nil && listenIP.IsLoopback()) || (listenHost == "localhost" && targetIP != nil && targetIP.IsLoopback())
	if listenHost == "" || (listenIP != nil && listenIP.IsUnspecified()) || targetHost == listenHost || sameIP || sameLoopback {
		return errors.New("public routes cannot target the Frontlane control listener")
	}
	return nil
}

func (s *server) writeRoutingFiles() error {
	services, err := s.store.listServices()
	if err != nil {
		return err
	}
	allowed, err := s.store.allowedServiceIPs()
	if err != nil {
		return err
	}
	proxy, hosts, err := buildRoutingConfigs(s.cfg, services, allowed)
	if err != nil {
		return err
	}
	if err := atomicWrite(s.cfg.CoreDNSHosts, hosts, 0644); err != nil {
		return err
	}
	return atomicWrite(s.cfg.TraefikDynamicFile, proxy, 0644)
}

func buildRoutingConfigs(cfg config, services []service, allowed map[int64][]string) ([]byte, []byte, error) {
	falseValue := false
	httpConfig := traefikHTTP{
		Routers: map[string]traefikRouter{
			"panel": {
				EntryPoints: []string{"websecure"},
				Rule:        fmt.Sprintf("Host(`panel.%s`)", cfg.BaseDomain),
				Service:     "privatewg-panel",
				TLS:         traefikTLS{CertResolver: "letsencrypt"},
			},
			"traefik-dashboard": {
				EntryPoints: []string{"websecure"},
				Rule:        fmt.Sprintf("Host(`panel.%s`) && PathPrefix(`/traefik`)", cfg.BaseDomain),
				Service:     "api@internal",
				Middlewares: []string{"panel-auth"},
				Priority:    100,
				TLS:         traefikTLS{CertResolver: "letsencrypt"},
			},
		},
		Middlewares: map[string]traefikMiddleware{
			"panel-auth": {
				ForwardAuth: &traefikForwardAuth{
					Address:                "http://10.77.0.1:8080/__privatewg/auth",
					TrustForwardHeader:     false,
					PreserveLocationHeader: true,
				},
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
			"public-service-errors": {
				Errors: &traefikErrors{
					Status:              []string{"502", "504"},
					Service:             "privatewg-errors",
					Query:               "/__privatewg/errors/{status}",
					ErrorRequestHeaders: []string{},
				},
			},
			"paused-route": {
				ReplacePath: &traefikReplacePath{Path: "/__privatewg/errors/503"},
			},
			"denied-route": {
				ReplacePath: &traefikReplacePath{Path: "/__privatewg/errors/403"},
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
			sourceRange := allowed[svc.ID]
			if svc.Public || len(sourceRange) > 0 {
				router.Service = name
				router.Middlewares = []string{"public-service-errors", "retry-upstream"}
				if !svc.Public {
					allowlistName := name + "-access"
					httpConfig.Middlewares[allowlistName] = traefikMiddleware{IPAllowList: &traefikIPAllowList{SourceRange: sourceRange, RejectStatusCode: 418}}
					router.Middlewares = []string{"service-errors", allowlistName, "retry-upstream"}
				}
				httpConfig.Services[name] = traefikService{
					LoadBalancer: traefikLoadBalancer{
						Servers:          []traefikServer{{URL: "http://" + svc.Target}},
						ServersTransport: "privatewg-upstream",
					},
				}
			} else {
				router.Service = "privatewg-errors"
				router.Middlewares = []string{"denied-route"}
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
	title := "Application unreachable"
	label := "UPSTREAM OFFLINE"
	message := "The gateway accepted this request, but the application upstream did not respond. Check the route target and its endpoint."
	switch status {
	case http.StatusForbidden:
		title = "Access denied"
		label = "POLICY REQUIRED"
		message = "This VPN connection is not authorized for this application. Connect through an enabled VPN connection with matching access."
	case http.StatusServiceUnavailable:
		title = "Route paused"
		label = "ROUTE PAUSED"
		message = "This application route has been paused by the gateway administrator."
	case http.StatusBadGateway, http.StatusGatewayTimeout:
	default:
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
	w.WriteHeader(status)
	fmt.Fprintf(w, `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="theme-color" content="#071e47"><title>%s - Frontlane</title><link rel="icon" href="data:image/svg+xml,%%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%%3E%%3Crect width='64' height='64' rx='16' fill='%%232f7df6'/%%3E%%3Crect x='19' y='28' width='6' height='16' rx='3' fill='white'/%%3E%%3Crect x='29' y='17' width='6' height='27' rx='3' fill='white'/%%3E%%3Crect x='39' y='23' width='6' height='21' rx='3' fill='white'/%%3E%%3C/svg%%3E">
<style>:root{color:#132b49;background:#071e47;font-family:"Avenir Next","Segoe UI Variable",sans-serif}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;padding:clamp(20px,5vw,64px);background:linear-gradient(rgba(132,183,255,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(132,183,255,.07) 1px,transparent 1px),radial-gradient(circle at 15%% 10%%,#176bd0 0,transparent 31rem),linear-gradient(145deg,#04142f 0%%,#0a3470 55%%,#0f58ae 100%%);background-size:42px 42px,42px 42px,auto,auto}.card{position:relative;width:min(760px,100%%);overflow:hidden;background:rgba(255,255,255,.98);border:1px solid rgba(255,255,255,.7);border-radius:24px;box-shadow:0 35px 90px rgba(2,16,40,.42)}.brand{display:flex;gap:12px;align-items:center;padding:24px 28px;border-bottom:1px solid #d5e2f1}.brand svg{width:42px;height:42px;flex:none;filter:drop-shadow(0 10px 14px rgba(47,125,246,.2))}.brand span{display:grid}.brand b{color:#0b2858;font-size:19px;letter-spacing:-.035em}.brand small{margin-top:2px;color:#5b718b;font:9px "SFMono-Regular",Consolas,monospace;letter-spacing:.13em;text-transform:uppercase}.content{position:relative;padding:clamp(34px,7vw,64px)}.code{position:absolute;top:18px;right:30px;color:#edf4ff;font-size:clamp(90px,21vw,190px);font-weight:800;line-height:1;letter-spacing:-.08em;user-select:none}.label{position:relative;display:inline-flex;padding:7px 10px;color:#155fcf;background:#eaf3ff;border:1px solid #c8ddf8;border-radius:7px;font:700 10px "SFMono-Regular",Consolas,monospace;letter-spacing:.15em}.copy{position:relative;max-width:570px}h1{margin:20px 0 14px;color:#0b2858;font-size:clamp(38px,7vw,62px);font-weight:650;line-height:.98;letter-spacing:-.05em}p{max-width:540px;margin:0;color:#5b718b;font-size:15px;line-height:1.7}.meta{display:flex;justify-content:space-between;gap:16px;margin-top:38px;padding-top:18px;border-top:1px solid #d5e2f1;color:#7890aa;font:10px "SFMono-Regular",Consolas,monospace}@media(max-width:520px){.brand{padding:19px 21px}.content{padding:34px 24px}.code{top:24px;right:22px;font-size:88px}.copy{max-width:100%%}.meta{display:grid;gap:7px}}@media(prefers-reduced-motion:no-preference){.card{animation:enter .38s ease-out both}.copy>*{animation:rise .42s ease-out both}.copy h1{animation-delay:.05s}.copy p{animation-delay:.1s}@keyframes enter{from{opacity:0;transform:translateY(14px)}}@keyframes rise{from{opacity:0;transform:translateY(8px)}}}</style></head>
<body><main class="card"><header class="brand"><svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="16" fill="#2f7df6"/><rect x="19" y="28" width="6" height="16" rx="3" fill="#fff"/><rect x="29" y="17" width="6" height="27" rx="3" fill="#fff"/><rect x="39" y="23" width="6" height="21" rx="3" fill="#fff"/></svg><span><b>Frontlane</b><small>Application edge</small></span></header><section class="content"><div class="code" aria-hidden="true">%d</div><div class="copy"><span class="label">%s</span><h1>%s</h1><p>%s</p><div class="meta"><span>Gateway response</span><span>HTTP %d</span></div></div></section></main></body></html>`, title, status, label, title, message, status)
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
