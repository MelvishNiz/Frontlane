package main

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type store struct{ db *sql.DB }

type peer struct {
	ID               int64
	Name             string
	Kind             string
	IP               string
	PublicKey        string
	ConfigCipher     []byte
	HasConfig        bool
	Enabled          bool
	Active           bool
	CreatedAt        time.Time
	LastHandshake    time.Time
	ReceivedBytes    int64
	TransmittedBytes int64
}

type service struct {
	ID        int64
	Host      string
	Target    string
	Enabled   bool
	CreatedAt time.Time
}

func openStore(path string) (*store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite3", path+"?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	statements := []string{
		`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, salt TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS peers (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL CHECK(kind IN ('client','server')), ip TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS services (id INTEGER PRIMARY KEY, host TEXT NOT NULL UNIQUE, target TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS audit_log (id INTEGER PRIMARY KEY, action TEXT NOT NULL, subject TEXT NOT NULL, remote_ip TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			db.Close()
			return nil, err
		}
	}
	for _, migration := range []struct{ table, column, definition string }{
		{"peers", "config_cipher", "BLOB"},
		{"peers", "enabled", "INTEGER NOT NULL DEFAULT 1"},
		{"services", "enabled", "INTEGER NOT NULL DEFAULT 1"},
	} {
		if err := ensureColumn(db, migration.table, migration.column, migration.definition); err != nil {
			db.Close()
			return nil, err
		}
	}
	return &store{db: db}, nil
}

func ensureColumn(db *sql.DB, table, column, definition string) error {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, kind string
		var notNull, pk int
		var defaultValue any
		if err := rows.Scan(&cid, &name, &kind, &notNull, &defaultValue, &pk); err != nil {
			return err
		}
		if name == column {
			return nil
		}
	}
	if err := rows.Close(); err != nil {
		return err
	}
	_, err = db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + column + ` ` + definition)
	return err
}

func (s *store) Close() error { return s.db.Close() }

func (s *store) ensureAdmin(username, password string) error {
	var count int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count); err != nil {
		return err
	}
	if count > 0 {
		return nil
	}
	if len(password) < 20 {
		return errors.New("PWG_ADMIN_PASSWORD must contain at least 20 characters")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT INTO users(username,password_hash,salt) VALUES(?,?,?)`, username, hashPassword(password, salt), base64.RawStdEncoding.EncodeToString(salt))
	return err
}

func (s *store) authenticate(username, password string) bool {
	var hash, saltText string
	if err := s.db.QueryRow(`SELECT password_hash,salt FROM users WHERE username=?`, username).Scan(&hash, &saltText); err != nil {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(saltText)
	return err == nil && subtleEqual(hash, hashPassword(password, salt))
}

func (s *store) listPeers() ([]peer, error) {
	rows, err := s.db.Query(`SELECT id,name,kind,ip,public_key,COALESCE(config_cipher,''),enabled,created_at FROM peers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []peer
	for rows.Next() {
		var p peer
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.IP, &p.PublicKey, &p.ConfigCipher, &p.Enabled, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.HasConfig = len(p.ConfigCipher) > 0
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *store) createPeer(name, kind, publicKey string) (peer, error) {
	peers, err := s.listPeers()
	if err != nil {
		return peer{}, err
	}
	used := map[string]bool{"10.77.0.1": true}
	for _, p := range peers {
		used[p.IP] = true
	}
	ip := ""
	for i := 2; i < 255; i++ {
		candidate := fmt.Sprintf("10.77.0.%d", i)
		if !used[candidate] {
			ip = candidate
			break
		}
	}
	if ip == "" {
		return peer{}, errors.New("subnet peer penuh")
	}
	result, err := s.db.Exec(`INSERT INTO peers(name,kind,ip,public_key) VALUES(?,?,?,?)`, name, kind, ip, publicKey)
	if err != nil {
		return peer{}, friendlyDBError(err)
	}
	id, _ := result.LastInsertId()
	return s.peerByID(id)
}

func (s *store) peerByID(id int64) (peer, error) {
	var p peer
	err := s.db.QueryRow(`SELECT id,name,kind,ip,public_key,COALESCE(config_cipher,''),enabled,created_at FROM peers WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.Kind, &p.IP, &p.PublicKey, &p.ConfigCipher, &p.Enabled, &p.CreatedAt)
	p.HasConfig = len(p.ConfigCipher) > 0
	return p, err
}

func (s *store) setPeerEnabled(id int64, enabled bool) error {
	result, err := s.db.Exec(`UPDATE peers SET enabled=? WHERE id=?`, enabled, id)
	if err == nil {
		if n, _ := result.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
	}
	return err
}

func (s *store) savePeerConfig(id int64, cipher []byte) error {
	_, err := s.db.Exec(`UPDATE peers SET config_cipher=? WHERE id=?`, cipher, id)
	return err
}

func (s *store) deletePeer(id int64) error {
	result, err := s.db.Exec(`DELETE FROM peers WHERE id=?`, id)
	if err == nil {
		if n, _ := result.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
	}
	return err
}

func (s *store) restorePeer(p peer) error {
	_, err := s.db.Exec(`INSERT INTO peers(id,name,kind,ip,public_key,config_cipher,enabled,created_at) VALUES(?,?,?,?,?,?,?,?)`, p.ID, p.Name, p.Kind, p.IP, p.PublicKey, p.ConfigCipher, p.Enabled, p.CreatedAt)
	return err
}

func (s *store) listServices() ([]service, error) {
	rows, err := s.db.Query(`SELECT id,host,target,enabled,created_at FROM services ORDER BY host`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []service
	for rows.Next() {
		var svc service
		if err := rows.Scan(&svc.ID, &svc.Host, &svc.Target, &svc.Enabled, &svc.CreatedAt); err != nil {
			return nil, err
		}
		result = append(result, svc)
	}
	return result, rows.Err()
}

func (s *store) createService(host, target string) (service, error) {
	result, err := s.db.Exec(`INSERT INTO services(host,target) VALUES(?,?)`, host, target)
	if err != nil {
		return service{}, friendlyDBError(err)
	}
	id, _ := result.LastInsertId()
	return s.serviceByID(id)
}

func (s *store) serviceByID(id int64) (service, error) {
	var svc service
	err := s.db.QueryRow(`SELECT id,host,target,enabled,created_at FROM services WHERE id=?`, id).Scan(&svc.ID, &svc.Host, &svc.Target, &svc.Enabled, &svc.CreatedAt)
	return svc, err
}

func (s *store) setServiceEnabled(id int64, enabled bool) error {
	result, err := s.db.Exec(`UPDATE services SET enabled=? WHERE id=?`, enabled, id)
	if err == nil {
		if n, _ := result.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
	}
	return err
}

func (s *store) deleteService(id int64) error {
	result, err := s.db.Exec(`DELETE FROM services WHERE id=?`, id)
	if err == nil {
		if n, _ := result.RowsAffected(); n == 0 {
			return sql.ErrNoRows
		}
	}
	return err
}

func (s *store) restoreService(svc service) error {
	_, err := s.db.Exec(`INSERT INTO services(id,host,target,enabled,created_at) VALUES(?,?,?,?,?)`, svc.ID, svc.Host, svc.Target, svc.Enabled, svc.CreatedAt)
	return err
}

func (s *store) audit(action, subject, remoteIP string) {
	_, _ = s.db.Exec(`INSERT INTO audit_log(action,subject,remote_ip) VALUES(?,?,?)`, action, subject, remoteIP)
}

func friendlyDBError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return errors.New("nama, domain, IP, atau public key sudah digunakan")
	}
	return err
}
