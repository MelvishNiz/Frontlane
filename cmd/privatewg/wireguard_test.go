package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEncryptedPeerConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	wgDir := filepath.Join(dir, "wireguard")
	if err := os.MkdirAll(wgDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(wgDir, "server.key"), []byte("test-server-private-key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	st, err := openStore(filepath.Join(dir, "privatewg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	result, err := st.db.Exec(`INSERT INTO peers(name,kind,ip,public_key) VALUES('phone','client','10.77.0.2','public-key')`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	s := &server{cfg: config{WGDir: wgDir}, store: st}
	want := "[Interface]\nPrivateKey = secret\n"
	if err := s.storeEncryptedConfig(id, want); err != nil {
		t.Fatal(err)
	}
	p, err := st.peerByID(id)
	if err != nil {
		t.Fatal(err)
	}
	if !p.HasConfig || bytes.Contains(p.ConfigCipher, []byte("secret")) {
		t.Fatal("config must exist only as ciphertext")
	}
	got, err := s.decryptedPeerConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("decrypted config = %q, want %q", got, want)
	}
}

func TestEnabledStateRoundTrip(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "privatewg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	p, err := st.createPeer("phone", "client", "public-key")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := st.createService("app.external.test", "10.77.0.20:80")
	if err != nil {
		t.Fatal(err)
	}
	if !p.Enabled || !svc.Enabled {
		t.Fatal("new peers and services must be enabled")
	}
	if err := st.setPeerEnabled(p.ID, false); err != nil {
		t.Fatal(err)
	}
	if err := st.setServiceEnabled(svc.ID, false); err != nil {
		t.Fatal(err)
	}
	p, _ = st.peerByID(p.ID)
	svc, _ = st.serviceByID(svc.ID)
	if p.Enabled || svc.Enabled {
		t.Fatal("disabled state must persist")
	}
}

func TestPeerActive(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	for _, test := range []struct {
		name      string
		enabled   bool
		handshake int64
		want      bool
	}{
		{"recent handshake", true, now.Add(-2 * time.Minute).Unix(), true},
		{"stale handshake", true, now.Add(-3 * time.Minute).Unix(), false},
		{"disabled peer", false, now.Add(-time.Minute).Unix(), false},
		{"future handshake", true, now.Add(time.Minute).Unix(), false},
		{"never connected", true, 0, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := peerActive(test.enabled, test.handshake, now); got != test.want {
				t.Fatalf("peerActive() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestLastHandshakePersists(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "privatewg.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p, err := st.createPeer("phone", "client", "public-key")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Unix(1_800_000_000, 0).UTC()
	if err := st.savePeerHandshake(p.ID, want); err != nil {
		t.Fatal(err)
	}
	got, err := st.peerByID(p.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.LastHandshake.Equal(want) {
		t.Fatalf("last handshake = %v, want %v", got.LastHandshake, want)
	}
}

func TestQRPNG(t *testing.T) {
	if _, err := os.Stat("/usr/bin/qrencode"); err != nil {
		t.Skip("qrencode unavailable")
	}
	png, err := qrPNG("[Interface]\nPrivateKey = secret\n")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(png, []byte("\x89PNG\r\n\x1a\n")) {
		t.Fatal("QR output is not PNG")
	}
}
