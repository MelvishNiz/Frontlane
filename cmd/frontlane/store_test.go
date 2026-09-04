package main

import (
	"bytes"
	"database/sql"
	"html/template"
	"io"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

func TestLegacyRoleMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		`CREATE TABLE peers (id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE, kind TEXT NOT NULL, ip TEXT NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`CREATE TABLE services (id INTEGER PRIMARY KEY, host TEXT NOT NULL UNIQUE, target TEXT NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
		`INSERT INTO peers(name,kind,ip,public_key) VALUES('legacy-peer','client','10.77.0.2','legacy-key')`,
		`INSERT INTO services(host,target) VALUES('legacy.example.com','10.77.0.20:80')`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	st, err := openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	assertCount(t, st.db, `SELECT COUNT(*) FROM roles WHERE name='All'`, 1)
	assertCount(t, st.db, `SELECT COUNT(*) FROM peer_roles`, 1)
	assertCount(t, st.db, `SELECT COUNT(*) FROM role_services`, 1)
	newRole, err := st.createRole("New peers", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.createPeer("new-peer", "client", "new-key", []int64{newRole.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := st.createService("new.example.com", "10.77.0.21:80", false); err != nil {
		t.Fatal(err)
	}
	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	st, err = openStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	assertCount(t, st.db, `SELECT COUNT(*) FROM schema_migrations WHERE version=1`, 1)
	assertCount(t, st.db, `SELECT COUNT(*) FROM peer_roles`, 2)
	assertCount(t, st.db, `SELECT COUNT(*) FROM peer_roles pr JOIN roles r ON r.id=pr.role_id WHERE r.name='All'`, 1)
	assertCount(t, st.db, `SELECT COUNT(*) FROM role_services`, 1)
	allowed, err := st.allowedServiceIPs()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(allowed[1]); got != 1 || allowed[1][0] != "10.77.0.2/32" {
		t.Fatalf("legacy allowed IPs = %#v", allowed[1])
	}
	if got := len(allowed[2]); got != 0 {
		t.Fatalf("new service received default access: %#v", allowed[2])
	}
	newService, err := st.serviceByID(2)
	if err != nil {
		t.Fatal(err)
	}
	if newService.Public {
		t.Fatal("existing and new services must default private")
	}
}

func TestRoleSharedAccessDefaultDenyAndCascade(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "roles.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	p1, err := st.createPeer("peer-one", "client", "key-one", []int64{testRoleID(t, st, "All")})
	if err != nil {
		t.Fatal(err)
	}
	p2, err := st.createPeer("peer-two", "client", "key-two", []int64{testRoleID(t, st, "All")})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := st.createService("app.example.com", "10.77.0.20:80", false)
	if err != nil {
		t.Fatal(err)
	}
	allowed, err := st.allowedServiceIPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed[svc.ID]) != 0 {
		t.Fatal("unassigned service must default deny")
	}
	r, err := st.createRole("Engineering", []int64{p1.ID}, []int64{svc.ID})
	if err != nil {
		t.Fatal(err)
	}
	allowed, err = st.allowedServiceIPs()
	if err != nil {
		t.Fatal(err)
	}
	if got := allowed[svc.ID]; len(got) != 1 || got[0] != p1.IP+"/32" {
		t.Fatalf("shared-role access = %#v", got)
	}
	if got := allowed[svc.ID]; len(got) > 0 && got[0] == p2.IP+"/32" {
		t.Fatal("peer without shared role received access")
	}
	if err := st.setPeerEnabled(p1.ID, false); err != nil {
		t.Fatal(err)
	}
	allowed, err = st.allowedServiceIPs()
	if err != nil {
		t.Fatal(err)
	}
	if len(allowed[svc.ID]) != 0 {
		t.Fatal("disabled peer must not receive access")
	}
	if err := st.replaceRole(r.ID, "Broken", []int64{9999}, []int64{svc.ID}); err == nil {
		t.Fatal("invalid replacement must fail")
	}
	unchanged, err := st.roleByID(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if unchanged.Name != r.Name || !unchanged.PeerIDs[p1.ID] || !unchanged.ServiceIDs[svc.ID] {
		t.Fatalf("failed replacement was not rolled back: %#v", unchanged)
	}
	if err := st.deletePeer(p1.ID); err != nil {
		t.Fatal(err)
	}
	assertCount(t, st.db, `SELECT COUNT(*) FROM peer_roles WHERE role_id=?`, 0, r.ID)
	if err := st.deleteService(svc.ID); err != nil {
		t.Fatal(err)
	}
	assertCount(t, st.db, `SELECT COUNT(*) FROM role_services WHERE role_id=?`, 0, r.ID)
	if _, err := st.createRole("Temporary", []int64{p2.ID}, nil); err != nil {
		t.Fatal(err)
	}
	var temporaryID int64
	if err := st.db.QueryRow(`SELECT id FROM roles WHERE name='Temporary'`).Scan(&temporaryID); err != nil {
		t.Fatal(err)
	}
	if _, err := st.deleteRole(temporaryID); err != nil {
		t.Fatal(err)
	}
	assertCount(t, st.db, `SELECT COUNT(*) FROM peer_roles WHERE role_id=?`, 0, temporaryID)
}

func TestPeerUpdateAndServerAccess(t *testing.T) {
	st, err := openStore(filepath.Join(t.TempDir(), "peer-update.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	roleID := testRoleID(t, st, "All")
	client, err := st.createPeerWithNote("laptop", "client", "client-key", "Initial note", []int64{roleID})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.updatePeer(client.ID, "work-laptop", "Alice's device", []int64{roleID}); err != nil {
		t.Fatal(err)
	}
	updated, err := st.peerByID(client.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Name != "work-laptop" || updated.Note != "Alice's device" || !updated.RoleIDs[roleID] || len(updated.RoleNames) != 1 {
		t.Fatalf("updated client = %#v", updated)
	}
	if err := st.updatePeer(client.ID, "work-laptop", "", nil); err == nil {
		t.Fatal("client update without access must fail")
	}
	server, err := st.createPeerWithNote("api", "server", "server-key", "Production", []int64{roleID})
	if err != nil {
		t.Fatal(err)
	}
	if len(server.RoleIDs) != 0 || len(server.RoleNames) != 0 {
		t.Fatalf("server received access: %#v", server)
	}
}

func TestSplitPeers(t *testing.T) {
	clients, servers := splitPeers([]peer{
		{ID: 1, Kind: "client"},
		{ID: 2, Kind: "server"},
		{ID: 3, Kind: "client"},
	})
	if len(clients) != 2 || len(servers) != 1 || servers[0].ID != 2 {
		t.Fatalf("unexpected split: clients=%v servers=%v", clients, servers)
	}
}

func TestVPNTemplateTabsAndURLs(t *testing.T) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"initial": initial,
		"bytes":   humanBytes,
		"ago":     timeAgo,
		"unix":    func(value time.Time) int64 { return value.Unix() },
		"internalDomain": func(string) bool {
			return true
		},
	}).ParseFS(assets, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	data := viewData{
		Title: "VPN connections", Section: "endpoints", User: "admin", CSRF: "token", VPNTab: "server",
		ClientPeers: []peer{{ID: 1, Name: "laptop", Kind: "client", RoleIDs: map[int64]bool{1: true}, RoleNames: []string{"Engineering"}}},
		ServerPeers: []peer{{ID: 2, Name: "api", Kind: "server", Note: "Production"}},
		VPNPeers:    []peer{{ID: 2, Name: "api", Kind: "server", Note: "Production"}},
		Roles:       []role{{ID: 1, Name: "Engineering", ServiceIDs: map[int64]bool{}}},
	}
	var rendered bytes.Buffer
	if err := tpl.ExecuteTemplate(&rendered, "vpn.html", data); err != nil {
		t.Fatal(err)
	}
	output := rendered.String()
	if !strings.Contains(output, `href="/vpn?tab=server"`) || !strings.Contains(output, `href="/vpn/2"`) || strings.Contains(output, "/peers") || strings.Contains(output, ">laptop<") {
		t.Fatal("VPN page must render the selected server tab with /vpn URLs only")
	}
	for _, expected := range []string{`id="server-create-dialog"`, `id="client-create-dialog"`, `id="peer-edit-2"`, `action="/vpn/2"`, `name="note"`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("VPN page missing %q", expected)
		}
	}
	if strings.Contains(output, `class="resource-header peer-columns server-peer-columns" aria-hidden="true"><span>Server</span><span>Gateway IP</span><span>Access</span>`) {
		t.Fatal("server table must not show access")
	}
	if strings.Contains(output, `class="directory-count"`) {
		t.Fatal("VPN page must not show a connection counter")
	}
	data.VPNTab, data.VPNPeers = "client", data.ClientPeers
	rendered.Reset()
	if err := tpl.ExecuteTemplate(&rendered, "vpn.html", data); err != nil {
		t.Fatal(err)
	}
	output = rendered.String()
	if !strings.Contains(output, `<span>Gateway IP</span><span>Access</span>`) || !strings.Contains(output, `Engineering`) || !strings.Contains(output, `name="role_ids"`) {
		t.Fatal("client table and dialogs must show editable access")
	}
}

func TestServicesTemplate(t *testing.T) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"initial": initial,
		"bytes":   humanBytes,
		"ago":     timeAgo,
		"unix":    func(value time.Time) int64 { return value.Unix() },
		"internalDomain": func(string) bool {
			return true
		},
	}).ParseFS(assets, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	data := viewData{
		Title: "Routes", Section: "routes", User: "admin", CSRF: "token", PanelDomain: "panel.example.com",
		Services: []service{{ID: 1, Host: "app.example.com", Target: "10.77.0.20:80", Enabled: true, Public: true, CreatedAt: time.Now()}},
	}
	var rendered bytes.Buffer
	if err := tpl.ExecuteTemplate(&rendered, "services.html", data); err != nil {
		t.Fatal(err)
	}
	output := rendered.String()
	for _, expected := range []string{`<b>Routes</b>`, `<span>Public</span><span>Enabled</span>`, `href="https://app.example.com"`, `href="#icon-language"`, `id="service-edit-1"`, `action="/services/1"`} {
		if !strings.Contains(output, expected) {
			t.Fatalf("routes page missing %q", expected)
		}
	}
	for _, removed := range []string{"Application routes", "DNS points traffic here", ">Open <", ">Live<", ">Access<", `class="directory-count"`} {
		if strings.Contains(output, removed) {
			t.Fatalf("routes page still contains %q", removed)
		}
	}
}

func TestRolesTemplate(t *testing.T) {
	tpl, err := template.New("").Funcs(template.FuncMap{
		"initial": initial,
		"bytes":   humanBytes,
		"ago":     timeAgo,
		"unix":    func(value time.Time) int64 { return value.Unix() },
		"internalDomain": func(string) bool {
			return true
		},
	}).ParseFS(assets, "web/templates/*.html")
	if err != nil {
		t.Fatal(err)
	}
	data := viewData{
		Title: "Roles", User: "admin", CSRF: "token", PanelDomain: "panel.example.com",
		Peers:    []peer{{ID: 1, Name: "laptop", IP: "10.77.0.2", Kind: "client", Enabled: true}},
		Services: []service{{ID: 1, Host: "app.example.com", Target: "10.77.0.20:80", Enabled: true}},
		Roles:    []role{{ID: 1, Name: "All", CreatedAt: time.Now(), PeerIDs: map[int64]bool{1: true}, ServiceIDs: map[int64]bool{1: true}}},
		Role:     role{ID: 1, Name: "All", PeerIDs: map[int64]bool{1: true}, ServiceIDs: map[int64]bool{1: true}},
	}
	var rendered bytes.Buffer
	data.Section = "access"
	if err := tpl.ExecuteTemplate(&rendered, "access.html", data); err != nil {
		t.Fatal(err)
	}
	output := rendered.String()
	if !strings.Contains(output, `href="/roles" aria-current="page"`) || !strings.Contains(output, `id="confirm-dialog"`) || strings.Contains(output, `class="identity"`) {
		t.Fatal("access navigation must be active, hide gateway identity, and include the shared confirmation dialog")
	}
	if !strings.Contains(output, `class="resource-header access-columns"`) || !strings.Contains(output, `id="access-edit-1"`) || !strings.Contains(output, `data-dialog-open="access-edit-1"><svg aria-hidden="true"><use href="#icon-edit"></use></svg> Edit`) || strings.Contains(output, `name="peer_ids"`) || strings.Contains(output, `class="directory-count"`) || !strings.Contains(output, `href="#icon-traefik"`) || !strings.Contains(output, `<b>Traefik</b>`) || !strings.Contains(output, `class="account-menu"`) || !strings.Contains(output, `data-confirm-title="Sign out of Frontlane?"`) {
		t.Fatal("access page must use a table, modal CRUD, route-only assignments, the Traefik sidebar action, and confirmed account logout")
	}
	data.Role = role{}
	if err := tpl.ExecuteTemplate(io.Discard, "access.html", data); err != nil {
		t.Fatal(err)
	}
}

func testRoleID(t *testing.T, st *store, name string) int64 {
	t.Helper()
	var id int64
	if err := st.db.QueryRow(`SELECT id FROM roles WHERE name=?`, name).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func assertCount(t *testing.T, db *sql.DB, query string, want int, args ...any) {
	t.Helper()
	var got int
	if err := db.QueryRow(query, args...).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("count for %q = %d, want %d", query, got, want)
	}
}
