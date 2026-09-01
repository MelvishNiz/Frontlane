package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
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
	config := s.clientConfig(p, privateKey)
	if err := s.storeEncryptedConfig(p.ID, config); err != nil {
		_ = s.store.deletePeer(p.ID)
		_ = s.applyWireGuard()
		return err
	}
	path := filepath.Join(s.cfg.DataDir, "bootstrap.conf")
	if err := atomicWrite(path, []byte(config), 0600); err != nil {
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
		if p.Enabled {
			fmt.Fprintf(&cfg, "\n[Peer]\n# %s\nPublicKey = %s\nAllowedIPs = %s/32\n", p.Name, p.PublicKey, p.IP)
		}
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
		if p := byKey[fields[0]]; p != nil {
			p.Active = peerActive(p.Enabled, handshake, time.Now())
			if p.Active {
				status.ActiveCount++
			}
			if handshake > 0 {
				latest := time.Unix(handshake, 0)
				if latest.After(p.LastHandshake) {
					_ = s.store.savePeerHandshake(p.ID, latest)
				}
				p.LastHandshake = latest
			}
			p.ReceivedBytes, p.TransmittedBytes = rx, tx
		}
	}
	return status, nil
}

func peerActive(enabled bool, handshake int64, now time.Time) bool {
	age := now.Sub(time.Unix(handshake, 0))
	return enabled && handshake > 0 && age >= 0 && age < 3*time.Minute
}

func (s *server) storeEncryptedConfig(peerID int64, config string) error {
	key, err := s.configEncryptionKey()
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	sealed := gcm.Seal(nonce, nonce, []byte(config), []byte("privatewg-peer-config"))
	return s.store.savePeerConfig(peerID, sealed)
}

func (s *server) decryptedPeerConfig(p peer) (string, error) {
	if len(p.ConfigCipher) == 0 {
		return "", errors.New("konfigurasi peer lama tidak tersimpan; buat ulang peer untuk mendapatkan config dan QR")
	}
	key, err := s.configEncryptionKey()
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(p.ConfigCipher) < gcm.NonceSize() {
		return "", errors.New("data konfigurasi peer rusak")
	}
	nonce, ciphertext := p.ConfigCipher[:gcm.NonceSize()], p.ConfigCipher[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, []byte("privatewg-peer-config"))
	if err != nil {
		return "", errors.New("konfigurasi peer tidak dapat didekripsi")
	}
	return string(plain), nil
}

func (s *server) configEncryptionKey() ([]byte, error) {
	serverKey, err := os.ReadFile(filepath.Join(s.cfg.WGDir, "server.key"))
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(append([]byte("privatewg/config/v1:"), bytes.TrimSpace(serverKey)...))
	return sum[:], nil
}

func qrPNG(config string) ([]byte, error) {
	cmd := exec.Command("qrencode", "-t", "PNG", "-o", "-", "-s", "7", "-m", "2", "-l", "M")
	cmd.Stdin = strings.NewReader(config)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("qrencode: %s", strings.TrimSpace(string(output)))
	}
	return output, nil
}

func run(name string, args ...string) error {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", name, strings.Join(args, " "), strings.TrimSpace(string(output)))
	}
	return nil
}
