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

type role struct {
	ID         int64
	Name       string
	CreatedAt  time.Time
	PeerIDs    map[int64]bool
	ServiceIDs map[int64]bool
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
		`CREATE TABLE IF NOT EXISTS roles (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE IF NOT EXISTS peer_roles (peer_id INTEGER NOT NULL REFERENCES peers(id) ON DELETE CASCADE, role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE, PRIMARY KEY(peer_id,role_id))`,
		`CREATE TABLE IF NOT EXISTS role_services (role_id INTEGER NOT NULL REFERENCES roles(id) ON DELETE CASCADE, service_id INTEGER NOT NULL REFERENCES services(id) ON DELETE CASCADE, PRIMARY KEY(role_id,service_id))`,
		`CREATE INDEX IF NOT EXISTS peer_roles_role_id ON peer_roles(role_id)`,
		`CREATE INDEX IF NOT EXISTS role_services_service_id ON role_services(service_id)`,
		`CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
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
		{"peers", "last_handshake", "DATETIME NOT NULL DEFAULT '0001-01-01T00:00:00Z'"},
		{"services", "enabled", "INTEGER NOT NULL DEFAULT 1"},
	} {
		if err := ensureColumn(db, migration.table, migration.column, migration.definition); err != nil {
			db.Close()
			return nil, err
		}
	}
	if err := migrateLegacyRoleAccess(db); err != nil {
		db.Close()
		return nil, err
	}
	return &store{db: db}, nil
}

func migrateLegacyRoleAccess(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var applied int
	err = tx.QueryRow(`SELECT 1 FROM schema_migrations WHERE version=1`).Scan(&applied)
	if err == nil {
		return tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO roles(name) VALUES('All')`); err != nil {
		return err
	}
	var roleID int64
	if err = tx.QueryRow(`SELECT id FROM roles WHERE name='All'`).Scan(&roleID); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO peer_roles(peer_id,role_id) SELECT id,? FROM peers`, roleID); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT OR IGNORE INTO role_services(role_id,service_id) SELECT ?,id FROM services`, roleID); err != nil {
		return err
	}
	if _, err = tx.Exec(`INSERT INTO schema_migrations(version) VALUES(1)`); err != nil {
		return err
	}
	return tx.Commit()
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
	rows, err := s.db.Query(`SELECT id,name,kind,ip,public_key,COALESCE(config_cipher,''),enabled,created_at,last_handshake FROM peers ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []peer
	for rows.Next() {
		var p peer
		if err := rows.Scan(&p.ID, &p.Name, &p.Kind, &p.IP, &p.PublicKey, &p.ConfigCipher, &p.Enabled, &p.CreatedAt, &p.LastHandshake); err != nil {
			return nil, err
		}
		p.HasConfig = len(p.ConfigCipher) > 0
		result = append(result, p)
	}
	return result, rows.Err()
}

func (s *store) createPeer(name, kind, publicKey string, roleIDs []int64) (peer, error) {
	if len(roleIDs) == 0 {
		return peer{}, errors.New("select at least one role")
	}
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
		return peer{}, errors.New("peer subnet is full")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return peer{}, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO peers(name,kind,ip,public_key) VALUES(?,?,?,?)`, name, kind, ip, publicKey)
	if err != nil {
		return peer{}, friendlyDBError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return peer{}, err
	}
	for _, roleID := range roleIDs {
		if _, err = tx.Exec(`INSERT INTO peer_roles(peer_id,role_id) VALUES(?,?)`, id, roleID); err != nil {
			return peer{}, friendlyDBError(err)
		}
	}
	if err := tx.Commit(); err != nil {
		return peer{}, err
	}
	return s.peerByID(id)
}

func (s *store) peerByID(id int64) (peer, error) {
	var p peer
	err := s.db.QueryRow(`SELECT id,name,kind,ip,public_key,COALESCE(config_cipher,''),enabled,created_at,last_handshake FROM peers WHERE id=?`, id).Scan(&p.ID, &p.Name, &p.Kind, &p.IP, &p.PublicKey, &p.ConfigCipher, &p.Enabled, &p.CreatedAt, &p.LastHandshake)
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

func (s *store) savePeerHandshake(id int64, handshake time.Time) error {
	_, err := s.db.Exec(`UPDATE peers SET last_handshake=? WHERE id=?`, handshake, id)
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

func (s *store) peerRoleIDs(peerID int64) ([]int64, error) {
	return queryIDs(s.db, `SELECT role_id FROM peer_roles WHERE peer_id=? ORDER BY role_id`, peerID)
}

func (s *store) restorePeer(p peer, roleIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO peers(id,name,kind,ip,public_key,config_cipher,enabled,created_at,last_handshake) VALUES(?,?,?,?,?,?,?,?,?)`, p.ID, p.Name, p.Kind, p.IP, p.PublicKey, p.ConfigCipher, p.Enabled, p.CreatedAt, p.LastHandshake); err != nil {
		return err
	}
	for _, roleID := range roleIDs {
		if _, err = tx.Exec(`INSERT INTO peer_roles(peer_id,role_id) VALUES(?,?)`, p.ID, roleID); err != nil {
			return err
		}
	}
	return tx.Commit()
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

func (s *store) serviceRoleIDs(serviceID int64) ([]int64, error) {
	return queryIDs(s.db, `SELECT role_id FROM role_services WHERE service_id=? ORDER BY role_id`, serviceID)
}

func (s *store) restoreService(svc service, roleIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO services(id,host,target,enabled,created_at) VALUES(?,?,?,?,?)`, svc.ID, svc.Host, svc.Target, svc.Enabled, svc.CreatedAt); err != nil {
		return err
	}
	for _, roleID := range roleIDs {
		if _, err = tx.Exec(`INSERT INTO role_services(role_id,service_id) VALUES(?,?)`, roleID, svc.ID); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *store) listRoles() ([]role, error) {
	rows, err := s.db.Query(`SELECT id,name,created_at FROM roles ORDER BY name COLLATE NOCASE,id`)
	if err != nil {
		return nil, err
	}
	var roles []role
	for rows.Next() {
		var r role
		if err := rows.Scan(&r.ID, &r.Name, &r.CreatedAt); err != nil {
			rows.Close()
			return nil, err
		}
		roles = append(roles, r)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	for i := range roles {
		peerIDs, serviceIDs, err := s.roleAssignmentIDs(roles[i].ID)
		if err != nil {
			return nil, err
		}
		roles[i].PeerIDs = idSet(peerIDs)
		roles[i].ServiceIDs = idSet(serviceIDs)
	}
	return roles, nil
}

func (s *store) roleByID(id int64) (role, error) {
	var r role
	if err := s.db.QueryRow(`SELECT id,name,created_at FROM roles WHERE id=?`, id).Scan(&r.ID, &r.Name, &r.CreatedAt); err != nil {
		return role{}, err
	}
	peerIDs, serviceIDs, err := s.roleAssignmentIDs(id)
	if err != nil {
		return role{}, err
	}
	r.PeerIDs, r.ServiceIDs = idSet(peerIDs), idSet(serviceIDs)
	return r, nil
}

func (s *store) createRole(name string, peerIDs, serviceIDs []int64) (role, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return role{}, err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`INSERT INTO roles(name) VALUES(?)`, name)
	if err != nil {
		return role{}, friendlyDBError(err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return role{}, err
	}
	if err := replaceRoleAssignments(tx, id, peerIDs, serviceIDs); err != nil {
		return role{}, friendlyDBError(err)
	}
	if err := tx.Commit(); err != nil {
		return role{}, err
	}
	return s.roleByID(id)
}

func (s *store) replaceRole(id int64, name string, peerIDs, serviceIDs []int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE roles SET name=? WHERE id=?`, name, id)
	if err != nil {
		return friendlyDBError(err)
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	if err := replaceRoleAssignments(tx, id, peerIDs, serviceIDs); err != nil {
		return friendlyDBError(err)
	}
	return tx.Commit()
}

func replaceRoleAssignments(tx *sql.Tx, roleID int64, peerIDs, serviceIDs []int64) error {
	if _, err := tx.Exec(`DELETE FROM peer_roles WHERE role_id=?`, roleID); err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM role_services WHERE role_id=?`, roleID); err != nil {
		return err
	}
	for _, peerID := range peerIDs {
		if _, err := tx.Exec(`INSERT INTO peer_roles(peer_id,role_id) VALUES(?,?)`, peerID, roleID); err != nil {
			return err
		}
	}
	for _, serviceID := range serviceIDs {
		if _, err := tx.Exec(`INSERT INTO role_services(role_id,service_id) VALUES(?,?)`, roleID, serviceID); err != nil {
			return err
		}
	}
	return nil
}

func (s *store) deleteRole(id int64) (role, error) {
	r, err := s.roleByID(id)
	if err != nil {
		return role{}, err
	}
	result, err := s.db.Exec(`DELETE FROM roles WHERE id=?`, id)
	if err != nil {
		return role{}, err
	}
	if n, _ := result.RowsAffected(); n == 0 {
		return role{}, sql.ErrNoRows
	}
	return r, nil
}

func (s *store) restoreRole(r role) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec(`INSERT INTO roles(id,name,created_at) VALUES(?,?,?)`, r.ID, r.Name, r.CreatedAt); err != nil {
		return err
	}
	if err = replaceRoleAssignments(tx, r.ID, setIDs(r.PeerIDs), setIDs(r.ServiceIDs)); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *store) roleAssignmentIDs(roleID int64) ([]int64, []int64, error) {
	peers, err := queryIDs(s.db, `SELECT peer_id FROM peer_roles WHERE role_id=? ORDER BY peer_id`, roleID)
	if err != nil {
		return nil, nil, err
	}
	services, err := queryIDs(s.db, `SELECT service_id FROM role_services WHERE role_id=? ORDER BY service_id`, roleID)
	return peers, services, err
}

func (s *store) allowedServiceIPs() (map[int64][]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT rs.service_id,p.ip FROM role_services rs JOIN peer_roles pr ON pr.role_id=rs.role_id JOIN peers p ON p.id=pr.peer_id WHERE p.enabled=1 ORDER BY rs.service_id,p.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	allowed := map[int64][]string{}
	for rows.Next() {
		var serviceID int64
		var ip string
		if err := rows.Scan(&serviceID, &ip); err != nil {
			return nil, err
		}
		allowed[serviceID] = append(allowed[serviceID], ip+"/32")
	}
	return allowed, rows.Err()
}

func queryIDs(db interface {
	Query(string, ...any) (*sql.Rows, error)
}, query string, arg any) ([]int64, error) {
	rows, err := db.Query(query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func idSet(ids []int64) map[int64]bool {
	result := make(map[int64]bool, len(ids))
	for _, id := range ids {
		result[id] = true
	}
	return result
}

func setIDs(values map[int64]bool) []int64 {
	ids := make([]int64, 0, len(values))
	for id := range values {
		ids = append(ids, id)
	}
	return ids
}

func (s *store) audit(action, subject, remoteIP string) {
	_, _ = s.db.Exec(`INSERT INTO audit_log(action,subject,remote_ip) VALUES(?,?,?)`, action, subject, remoteIP)
}

func friendlyDBError(err error) error {
	if strings.Contains(err.Error(), "UNIQUE constraint failed") {
		return errors.New("name, domain, IP, or public key is already in use")
	}
	if strings.Contains(err.Error(), "FOREIGN KEY constraint failed") {
		return errors.New("selected peer or domain no longer exists")
	}
	return err
}
