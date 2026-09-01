package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

type wgStatus struct {
	Running     bool
	PublicKey   string
	ListenPort  string
	PeerCount   int
	ActiveCount int
	Received    int64
	Transmitted int64
}

func (s *server) ensureWireGuard() error {
	if err := os.MkdirAll(s.cfg.WGDir, 0700); err != nil {
		return err
	}
	privatePath := filepath.Join(s.cfg.WGDir, "server.key")
	if _, err := os.Stat(privatePath); errors.Is(err, os.ErrNotExist) {
		private, _, err := generateKeyPair()
		if err != nil {
			return err
		}
		if err := os.WriteFile(privatePath, []byte(private+"\n"), 0600); err != nil {
			return err
		}
	}
	if err := s.applyWireGuard(); err != nil {
		return err
	}
	return nil
}

func (s *server) ensureBootstrapPeer() error {
	peers, err := s.store.listPeers()
	if err != nil || len(peers) > 0 {
		return err
	}
	privateKey, publicKey, err := generateKeyPair()
	if err != nil {
		return err
	}
	p, err := s.store.createPeer("bootstrap-admin", "client", publicKey)
	if err != nil {
		return err
	}
	if err := s.applyWireGuard(); err != nil {
		_ = s.store.deletePeer(p.ID)
		return err
	}
	path := filepath.Join(s.cfg.DataDir, "bootstrap.conf")
	if err := atomicWrite(path, []byte(s.clientConfig(p, privateKey)), 0600); err != nil {
		return err
	}
	log.Printf("bootstrap peer created: copy %s securely, then delete the file", path)
	return nil
}

func generateKeyPair() (string, string, error) {
	privateBytes, err := exec.Command("wg", "genkey").Output()
	if err != nil {
		return "", "", fmt.Errorf("wg genkey: %w", err)
	}
	private := strings.TrimSpace(string(privateBytes))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = strings.NewReader(private + "\n")
	publicBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("wg pubkey: %w", err)
	}
	return private, strings.TrimSpace(string(publicBytes)), nil
}

func (s *server) applyWireGuard() error {
	peers, err := s.store.listPeers()
	if err != nil {
		return err
	}
	privateBytes, err := os.ReadFile(filepath.Join(s.cfg.WGDir, "server.key"))
	if err != nil {
		return err
	}
	var cfg strings.Builder
	fmt.Fprintf(&cfg, "[Interface]\nPrivateKey = %s\nListenPort = 51820\n", strings.TrimSpace(string(privateBytes)))
	for _, p := range peers {
		fmt.Fprintf(&cfg, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n", p.Name, p.PublicKey, p.IP)
	}
	path := filepath.Join(s.cfg.WGDir, "wg0.conf")
	if err := atomicWrite(path, []byte(cfg.String()), 0600); err != nil {
		return err
	}
	strip, err := exec.Command("wg-quick", "strip", path).Output()
	if err != nil {
		return fmt.Errorf("validate wg0.conf: %w", err)
	}
	if err := exec.Command("ip", "link", "show", "wg0").Run(); err != nil {
		if err := run("ip", "link", "add", "wg0", "type", "wireguard"); err != nil {
			return err
		}
	}
	tempPath := filepath.Join(s.cfg.WGDir, ".wg0.runtime")
	if err := os.WriteFile(tempPath, strip, 0600); err != nil {
		return err
	}
	defer os.Remove(tempPath)
	if err := run("wg", "syncconf", "wg0", tempPath); err != nil {
		return err
	}
	_ = run("ip", "address", "replace", "10.77.0.1/24", "dev", "wg0")
	return run("ip", "link", "set", "up", "dev", "wg0")
}

func (s *server) clientConfig(p peer, privateKey string) string {
	serverPrivate, _ := os.ReadFile(filepath.Join(s.cfg.WGDir, "server.key"))
	cmd := exec.Command("wg", "pubkey")
	cmd.Stdin = bytes.NewReader(serverPrivate)
	serverPublicBytes, _ := cmd.Output()
	allowed := "10.77.0.0/24"
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/32
DNS = 10.77.0.1

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = %s
PersistentKeepalive = 25
`, privateKey, p.IP, strings.TrimSpace(string(serverPublicBytes)), s.cfg.PublicEndpoint, allowed)
}

func (s *server) wireGuardStatus(peers []peer) (wgStatus, error) {
	status := wgStatus{PeerCount: len(peers)}
	output, err := exec.Command("wg", "show", "wg0", "dump").Output()
	if err != nil {
		return status, err
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return status, nil
	}
	status.Running = true
	iface := strings.Split(lines[0], "\t")
	if len(iface) >= 4 {
		status.PublicKey, status.ListenPort = iface[1], iface[3]
	}
	byKey := make(map[string]*peer, len(peers))
	for i := range peers {
		byKey[peers[i].PublicKey] = &peers[i]
	}
	for _, line := range lines[1:] {
		fields := strings.Split(line, "\t")
		if len(fields) < 8 {
			continue
		}
		handshake, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)
		status.Received += rx
		status.Transmitted += tx
		if handshake > 0 && time.Since(time.Unix(handshake, 0)) < 3*time.Minute {
			status.ActiveCount++
		}
		if p := byKey[fields[0]]; p != nil {
			if handshake > 0 {
				p.LastHandshake = time.Unix(handshake, 0)
			}
			p.ReceivedBytes, p.TransmittedBytes = rx, tx
		}
	}
	return status, nil
}

func qrDataURL(config string) (string, error) {
	output, err := exec.Command("qrencode", "-t", "PNG", "-o", "-", "-s", "5", config).Output()
	if err != nil {
		return "", nil // QR optional; config remains downloadable by copy.
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(output), nil
}

func run(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return nil
}
