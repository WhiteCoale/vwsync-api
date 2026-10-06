//go:build e2e

// Package e2e testet das gebaute Binary gegen ein echtes Vaultwarden zum Wegwerfen.
//
//	docker run -d --rm --name vwsync-e2e -p 127.0.0.1:18082:80 \
//	  -e DOMAIN=http://127.0.0.1:18082 -e I_REALLY_WANT_VOLATILE_STORAGE=true \
//	  -e LOGIN_RATELIMIT_MAX_BURST=1000 -e LOGIN_RATELIMIT_SECONDS=1 vaultwarden/server:latest
//	VW_E2E_URL=http://127.0.0.1:18082 go test -tags e2e -count=1 -v ./e2e
//
// Der Test registriert eigene Konten mit zufälligen Passwörtern. Ist die Bitwarden-CLI (bw)
// installiert, dient sie als unabhängiger Client. Kann bw sich anmelden und lesen, was der Dienst
// geschrieben hat, stimmen die Verschlüsselungsformate. bw läuft mit eigenem Datenverzeichnis und
// fasst die Konfiguration des Benutzers nie an.
package e2e

import (
	"bytes"
	"context"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"vwsync-api/internal/crypto"
	"vwsync-api/internal/vaultwarden"
)

var vwURL = os.Getenv("VW_E2E_URL")

// --- Vaultwarden-Konten -------------------------------------------------------------------------

type account struct {
	email, password string
	kdf             crypto.KDFParams
	userKey         []byte
	priv            *rsa.PrivateKey

	// Schlüsselmaterial, das bei der Registrierung an den Server geht.
	encUserKey, publicKey, encPrivateKey string
}

func randHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (a account) masterKey(t *testing.T) []byte {
	t.Helper()
	mk, err := crypto.DeriveMasterKey(a.password, a.email, a.kdf)
	if err != nil {
		t.Fatal(err)
	}
	return mk
}

// authHash speichert der Server statt des Passworts: PBKDF2(masterKey, password, 1 Runde).
func (a account) authHash(t *testing.T) string {
	t.Helper()
	h, err := pbkdf2.Key(sha256.New, string(a.masterKey(t)), []byte(a.password), 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(h)
}

func postJSON(t *testing.T, path string, token string, body any, accept string) (int, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest("POST", vwURL+path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	return do(t, req)
}

func do(t *testing.T, req *http.Request) (int, []byte) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, b
}

// newAccount erzeugt die Schlüssel eines Kontos, ohne dem Server etwas mitzuteilen. Ein Konto, das nur
// so existiert, steht für eine Person, die sich noch nicht registriert hat.
func newAccount(t *testing.T, kdf crypto.KDFParams) account {
	t.Helper()
	a := account{email: "u" + randHex(4) + "@example.test", password: randHex(16), kdf: kdf}
	stretched, err := crypto.StretchMasterKey(a.masterKey(t))
	if err != nil {
		t.Fatal(err)
	}
	a.userKey = make([]byte, 64)
	_, _ = rand.Read(a.userKey)
	a.encUserKey, _ = crypto.EncryptSymmetric(a.userKey, stretched)
	a.priv, _ = rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(a.priv)
	pub, _ := x509.MarshalPKIXPublicKey(&a.priv.PublicKey)
	a.publicKey = base64.StdEncoding.EncodeToString(pub)
	a.encPrivateKey, _ = crypto.EncryptSymmetric(der, a.userKey)
	return a
}

// signUp registriert das Konto auf dem Server, so wie eine Person es im Web-Vault tut.
func (a account) signUp(t *testing.T) {
	t.Helper()
	code, body := postJSON(t, "/identity/accounts/register/send-verification-email",
		"", map[string]any{"email": a.email, "name": "e2e", "receiveMarketingEmails": false}, "application/json")
	if code != 200 {
		t.Fatalf("send-verification-email: %d %s", code, body)
	}
	var token string
	_ = json.Unmarshal(body, &token)

	reg := map[string]any{
		"email":                  a.email,
		"emailVerificationToken": token,
		"masterPasswordHash":     a.authHash(t),
		"key":                    a.encUserKey,
		"kdf":                    a.kdf.Type,
		"kdfIterations":          a.kdf.Iterations,
		"keys":                   map[string]string{"publicKey": a.publicKey, "encryptedPrivateKey": a.encPrivateKey},
	}
	if a.kdf.Type == crypto.KDFArgon2id {
		reg["kdfMemory"], reg["kdfParallelism"] = a.kdf.MemoryMiB, a.kdf.Parallelism
	}
	if code, body := postJSON(t, "/identity/accounts/register/finish", "", reg, ""); code != 200 {
		t.Fatalf("register/finish: %d %s", code, body)
	}
}

func register(t *testing.T, kdf crypto.KDFParams) account {
	t.Helper()
	a := newAccount(t, kdf)
	a.signUp(t)
	return a
}

// passwordToken meldet sich wie ein Web-Client an und liefert ein Access-Token.
func (a account) passwordToken(t *testing.T) string {
	t.Helper()
	form := url.Values{
		"grant_type": {"password"}, "username": {a.email}, "password": {a.authHash(t)},
		"scope": {"api offline_access"}, "client_id": {"web"}, "deviceType": {"9"},
		"deviceIdentifier": {"00000000-0000-4000-8000-" + randHex(6)}, "deviceName": {"e2e"},
	}
	req, _ := http.NewRequest("POST", vwURL+"/identity/connect/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	code, body := do(t, req)
	if code != 200 {
		t.Fatalf("password login: %d %s", code, body)
	}
	var r struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.Unmarshal(body, &r)
	return r.AccessToken
}

func (a account) get(t *testing.T, token, path string, out any) {
	t.Helper()
	req, _ := http.NewRequest("GET", vwURL+path, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	code, body := do(t, req)
	if code != 200 {
		t.Fatalf("GET %s: %d %s", path, code, body)
	}
	if err := json.Unmarshal(body, out); err != nil {
		t.Fatal(err)
	}
}

// apiKey liefert den persönlichen API-Key (client_id, client_secret) des Kontos.
func (a account) apiKey(t *testing.T) (string, string) {
	t.Helper()
	tok := a.passwordToken(t)
	var profile struct{ ID string }
	a.get(t, tok, "/api/accounts/profile", &profile)
	code, body := postJSON(t, "/api/accounts/api-key", tok, map[string]string{"masterPasswordHash": a.authHash(t)}, "")
	if code != 200 {
		t.Fatalf("api-key: %d %s", code, body)
	}
	var r struct{ ApiKey string }
	_ = json.Unmarshal(body, &r)
	return "user." + profile.ID, r.ApiKey
}

// serverVersion liefert Haupt- und Nebenversion des getesteten Vaultwarden (nicht der Bitwarden-API).
func serverVersion(t *testing.T) [2]int {
	t.Helper()
	req, _ := http.NewRequest("GET", vwURL+"/api/version", nil)
	code, body := do(t, req)
	var ver string
	var v [2]int
	if code != 200 || json.Unmarshal(body, &ver) != nil {
		t.Fatalf("GET /api/version: %d %s", code, body)
	}
	if _, err := fmt.Sscanf(ver, "%d.%d", &v[0], &v[1]); err != nil {
		t.Fatalf("cannot read server version %q", ver)
	}
	return v
}

// --- bw (unabhängiger Client) -------------------------------------------------------------------

type bw struct {
	t   *testing.T
	dir string
	env []string
}

// tlsProxy setzt einen HTTPS-Zugang mit selbstsigniertem Zertifikat vor das Test-Vaultwarden, weil bw
// http:// ablehnt. Geliefert werden die HTTPS-URL und der Pfad des Zertifikats, dem bw vertrauen muss.
func tlsProxy(t *testing.T) (string, string) {
	t.Helper()
	target, _ := url.Parse(vwURL)
	srv := httptest.NewTLSServer(httputil.NewSingleHostReverseProxy(target))
	t.Cleanup(srv.Close)
	pemFile := filepath.Join(t.TempDir(), "proxy.pem")
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	if err := os.WriteFile(pemFile, pemData, 0o600); err != nil {
		t.Fatal(err)
	}
	return srv.URL, pemFile
}

func newBW(t *testing.T) *bw {
	if _, err := exec.LookPath("bw"); err != nil {
		return nil
	}
	httpsURL, certFile := tlsProxy(t)
	b := &bw{t: t, dir: t.TempDir()}
	b.env = append(os.Environ(), "BITWARDENCLI_APPDATA_DIR="+b.dir, "BW_NOINTERACTION=true", "NODE_NO_WARNINGS=1",
		"NODE_EXTRA_CA_CERTS="+certFile)
	if out, err := b.run(nil, "config", "server", httpsURL); err != nil {
		t.Fatalf("bw config: %v %s", err, out)
	}
	return b
}

func (b *bw) run(extraEnv []string, args ...string) ([]byte, error) {
	cmd := exec.Command("bw", args...)
	cmd.Env = append(append([]string{}, b.env...), extraEnv...)
	return cmd.CombinedOutput()
}

// login liefert einen Sitzungsschlüssel. Das Passwort läuft über eine Umgebungsvariable, nie über
// die Kommandozeile.
func (b *bw) login(a account) string {
	b.t.Helper()
	out, err := b.run([]string{"BW_PASSWORD=" + a.password}, "login", a.email, "--passwordenv", "BW_PASSWORD", "--raw")
	if err != nil {
		b.t.Fatalf("bw login as %s failed: %v\n%s", a.email, err, scrub(out, a))
	}
	return strings.TrimSpace(string(out))
}

func (b *bw) json(session string, out any, args ...string) {
	b.t.Helper()
	res, err := b.run(nil, append(args, "--session", session)...)
	if err != nil {
		b.t.Fatalf("bw %v: %v\n%s", args, err, res)
	}
	if err := json.Unmarshal(res, out); err != nil {
		b.t.Fatalf("bw %v: not JSON: %s", args, res)
	}
}

func scrub(b []byte, a account) string {
	return strings.ReplaceAll(string(b), a.password, "<password>")
}

// --- der getestete Dienst -----------------------------------------------------------------------

type svc struct {
	t     *testing.T
	base  string
	token string
}

func startService(t *testing.T, admin account) *svc {
	t.Helper()
	root, _ := filepath.Abs("..")
	bin := filepath.Join(t.TempDir(), "vwsync-api")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	build := exec.Command("go", "build", "-o", bin, "./cmd/vwsync-api")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}

	// Der Schlüssel entsteht so, wie ein Betreiber ihn erzeugt, mit dem Befehl generate-key.
	out, err := exec.Command(bin, "generate-key").Output()
	if err != nil {
		t.Fatalf("generate-key: %v", err)
	}
	var apiKey, keyHash string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "vwsk_"):
			apiKey = line
		case strings.HasPrefix(line, "VWSYNC_API_KEY_HASH="):
			keyHash = strings.TrimPrefix(line, "VWSYNC_API_KEY_HASH=")
		}
	}
	if apiKey == "" || keyHash == "" {
		t.Fatalf("generate-key printed no key or no hash:\n%s", out)
	}

	clientID, secret := admin.apiKey(t)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	_ = ln.Close()

	cmd := exec.Command(bin, "serve")
	cmd.Env = append(os.Environ(),
		"VWSYNC_LISTEN="+addr, "VWSYNC_API_KEY_HASH="+keyHash, "VW_URL="+vwURL, "VW_CLIENT_ID="+clientID, "VW_CLIENT_SECRET="+secret,
		"VW_MASTER_PASSWORD="+admin.password)
	var logs bytes.Buffer
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("service log:\n%s", logs.String())
		}
	})

	s := &svc{t: t, base: "http://" + addr, token: apiKey}
	for i := 0; ; i++ {
		if resp, err := http.Get(s.base + "/healthz"); err == nil {
			_ = resp.Body.Close()
			break
		}
		if i > 100 {
			t.Fatalf("service did not start:\n%s", logs.String())
		}
		time.Sleep(100 * time.Millisecond)
	}

	return s
}

func (s *svc) call(method, path string, body any) (int, map[string]any) {
	s.t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, s.base+path, rd)
	if s.token != "" {
		req.Header.Set("Authorization", "Bearer "+s.token)
	}
	code, raw := do(s.t, req)
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		s.t.Fatalf("%s %s: not JSON (%d): %s", method, path, code, raw)
	}
	return code, out
}

func (s *svc) expect(want int, method, path string, body any) map[string]any {
	s.t.Helper()
	code, out := s.call(method, path, body)
	if code != want {
		s.t.Fatalf("%s %s: got %d, want %d: %v", method, path, code, want, out)
	}
	return out
}

func desired(org string, members map[string]string) map[string]any {
	return map[string]any{"orgs": map[string]any{org: map[string]any{"members": members}}}
}

// --- der Test -----------------------------------------------------------------------------------

func TestEndToEnd(t *testing.T) {
	if vwURL == "" {
		t.Skip("VW_E2E_URL not set")
	}
	pbkdf2Params := crypto.KDFParams{Type: crypto.KDFPBKDF2, Iterations: 600000}
	admin := register(t, pbkdf2Params)
	member := register(t, pbkdf2Params)
	s := startService(t, admin)
	const orgName = "E2E Team"

	t.Run("auth is enforced", func(t *testing.T) {
		anon := &svc{t: t, base: s.base}
		if code, _ := anon.call("GET", "/v1/orgs", nil); code != 401 {
			t.Fatalf("no token: %d", code)
		}
		wrong := &svc{t: t, base: s.base, token: "vwsk_" + strings.Repeat("A", 43)}
		if code, _ := wrong.call("GET", "/v1/orgs", nil); code != 401 {
			t.Fatalf("wrong key: %d", code)
		}
		if code, _ := s.call("GET", "/v1/orgs", nil); code != 200 {
			t.Fatalf("the generated key: %d", code)
		}
	})

	t.Run("no orgs yet", func(t *testing.T) {
		out := s.expect(200, "GET", "/v1/orgs", nil)
		if len(out["orgs"].([]any)) != 0 {
			t.Fatalf("%v", out)
		}
	})

	var orgID string
	t.Run("create org", func(t *testing.T) {
		out := s.expect(200, "POST", "/v1/orgs?dry_run=true", map[string]string{"name": orgName})
		if out["dry_run"] != true {
			t.Fatalf("dry run is not the default: %v", out)
		}
		if len(s.expect(200, "GET", "/v1/orgs", nil)["orgs"].([]any)) != 0 {
			t.Fatal("dry run created an org")
		}
		out = s.expect(201, "POST", "/v1/orgs", map[string]string{"name": orgName})
		orgID = out["org"].(map[string]any)["id"].(string)
		if orgID == "" {
			t.Fatalf("%v", out)
		}
		s.expect(409, "POST", "/v1/orgs", map[string]string{"name": "e2e team"})
		if got := s.expect(200, "GET", "/v1/orgs", nil)["orgs"].([]any); len(got) != 1 {
			t.Fatalf("expected exactly one org, got %v", got)
		}
	})

	t.Run("org keys are valid for the owner", func(t *testing.T) {
		tok := admin.passwordToken(t)
		var sync struct {
			Profile struct {
				Organizations []struct{ ID, Key string }
			}
		}
		admin.get(t, tok, "/api/sync", &sync)
		if len(sync.Profile.Organizations) != 1 {
			t.Fatalf("%+v", sync)
		}
		orgKey, err := crypto.DecryptAsymmetric(sync.Profile.Organizations[0].Key, admin.priv)
		if err != nil || len(orgKey) != 64 {
			t.Fatalf("owner cannot open the organization key: %v", err)
		}
		var cols struct{ Data []struct{ Name string } }
		admin.get(t, tok, "/api/organizations/"+orgID+"/collections", &cols)
		if len(cols.Data) != 1 {
			t.Fatalf("%+v", cols)
		}
		name, err := crypto.DecryptSymmetric(cols.Data[0].Name, orgKey)
		if err != nil || string(name) != "Default collection" {
			t.Fatalf("collection name: %q %v", name, err)
		}
	})

	t.Run("bw reads what the service wrote", func(t *testing.T) {
		b := newBW(t)
		if b == nil {
			t.Skip("bw not installed")
		}
		session := b.login(admin)
		var orgs []struct{ ID, Name string }
		b.json(session, &orgs, "list", "organizations")
		if len(orgs) != 1 || orgs[0].Name != orgName {
			t.Fatalf("%+v", orgs)
		}
		var cols []struct{ Name string }
		b.json(session, &cols, "list", "org-collections", "--organizationid", orgID)
		if len(cols) != 1 || cols[0].Name != "Default collection" {
			t.Fatalf("bw cannot decrypt the collection the service created: %+v", cols)
		}
	})

	t.Run("sync: preview, execute, idempotent", func(t *testing.T) {
		want := desired(orgName, map[string]string{member.email: "user"})
		out := s.expect(200, "POST", "/v1/sync?dry_run=true", want)
		if !strings.Contains(fmt.Sprint(out), "invite") {
			t.Fatalf("plan has no invite: %v", out)
		}
		s.expect(200, "POST", "/v1/sync", want)
		s.expect(400, "POST", "/v1/sync?apply=false", want) // der Parameter apply wird abgelehnt, nicht ignoriert
		again := s.expect(200, "POST", "/v1/sync?dry_run=true", want)
		if len(again["plans"].([]any)[0].(map[string]any)["changes"].([]any)) != 0 {
			t.Fatalf("second plan is not empty: %v", again)
		}
	})

	var memberStatus string
	t.Run("member is listed", func(t *testing.T) {
		out := s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)
		for _, m := range out["members"].([]any) {
			if m := m.(map[string]any); m["email"] == member.email {
				memberStatus = m["status"].(string)
			}
		}
		t.Logf("member status after invite (mail disabled): %q", memberStatus)
		if memberStatus == "" {
			t.Fatalf("member missing: %v", out)
		}
	})

	t.Run("confirm", func(t *testing.T) {
		if memberStatus != "accepted" {
			t.Skipf("member is %q, not accepted: the server needs the invite mail link to accept", memberStatus)
		}
		s.expect(400, "POST", "/v1/confirm", nil)
		dry := s.expect(200, "POST", "/v1/confirm?dry_run=true", map[string][]string{"emails": {member.email}})
		if !strings.Contains(fmt.Sprint(dry), member.email) {
			t.Fatalf("%v", dry)
		}
		out := s.expect(200, "POST", "/v1/confirm", map[string][]string{"emails": {member.email}})
		if out["failures"] != float64(0) {
			t.Fatalf("%v", out)
		}
		members := s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)["members"].([]any)
		for _, m := range members {
			if m := m.(map[string]any); m["email"] == member.email && m["status"] != "confirmed" {
				t.Fatalf("not confirmed: %v", m)
			}
		}

		// Das Mitglied kann den Organisations-Schlüssel mit seinem privaten Schlüssel öffnen, und es ist
		// derselbe wie der des Owners.
		ownerTok, memberTok := admin.passwordToken(t), member.passwordToken(t)
		type syncResp struct {
			Profile struct{ Organizations []struct{ Key string } }
		}
		var o, m syncResp
		admin.get(t, ownerTok, "/api/sync", &o)
		member.get(t, memberTok, "/api/sync", &m)
		if len(m.Profile.Organizations) != 1 {
			t.Fatalf("member sees %d orgs", len(m.Profile.Organizations))
		}
		ownerKey, _ := crypto.DecryptAsymmetric(o.Profile.Organizations[0].Key, admin.priv)
		memberKey, err := crypto.DecryptAsymmetric(m.Profile.Organizations[0].Key, member.priv)
		if err != nil || !bytes.Equal(ownerKey, memberKey) {
			t.Fatalf("confirm gave the member a wrong key: %v", err)
		}
	})

	t.Run("custom role manages all collections, manager and user do not", func(t *testing.T) {
		if memberStatus != "accepted" {
			t.Skip("member was not confirmed")
		}
		roleOf := func() string {
			for _, m := range s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)["members"].([]any) {
				if m := m.(map[string]any); m["email"] == member.email {
					return m["role"].(string)
				}
			}
			return "gone"
		}
		memberTok := member.passwordToken(t)
		var sync struct {
			Profile struct{ Organizations []struct{ Key string } }
		}
		member.get(t, memberTok, "/api/sync", &sync)
		orgKey, err := crypto.DecryptAsymmetric(sync.Profile.Organizations[0].Key, member.priv)
		if err != nil {
			t.Fatal(err)
		}
		// createCollection liefert den HTTP-Status, den das Mitglied beim Anlegen einer Sammlung erhält.
		createCollection := func() (int, string) {
			name, _ := crypto.EncryptSymmetric([]byte("made by "+randHex(3)), orgKey)
			code, body := postJSON(t, "/api/organizations/"+orgID+"/collections", memberTok,
				map[string]any{"name": name, "groups": []any{}, "users": []any{}}, "")
			var r struct{ ID string }
			_ = json.Unmarshal(body, &r)
			return code, r.ID
		}
		setRole := func(role string) {
			s.expect(200, "POST", "/v1/sync?no_remove=true", desired(orgName, map[string]string{member.email: role}))
			if got := roleOf(); got != role {
				t.Fatalf("after setting %s the listing says %s", role, got)
			}
			again := s.expect(200, "POST", "/v1/sync?dry_run=true&no_remove=true", desired(orgName, map[string]string{member.email: role}))
			if len(again["plans"].([]any)[0].(map[string]any)["changes"].([]any)) != 0 {
				t.Fatalf("%s is not idempotent: %v", role, again)
			}
		}

		setRole("custom")
		code, colID := createCollection()
		if code != 200 || colID == "" {
			t.Fatalf("a custom member with manage-all-collections must create collections, got %d", code)
		}
		req, _ := http.NewRequest("DELETE", vwURL+"/api/organizations/"+orgID+"/collections/"+colID, nil)
		req.Header.Set("Authorization", "Bearer "+memberTok)
		if code, body := do(t, req); code != 200 {
			t.Fatalf("custom member cannot delete the collection: %d %s", code, body)
		}

		// Vaultwarden 1.35 lässt einen Manager ohne "Alle Sammlungen verwalten" noch Sammlungen anlegen.
		// Die Sperre kam mit 1.37, deshalb wird die Ablehnung erst ab dieser Version geprüft.
		ver := serverVersion(t)
		for _, role := range []string{"manager", "user"} {
			setRole(role)
			code, _ := createCollection()
			switch {
			case code != 200:
			case role == "manager" && (ver[0] < 1 || ver[0] == 1 && ver[1] < 37):
				t.Logf("Vaultwarden %d.%d lets a manager create collections; not asserted on this version", ver[0], ver[1])
			default:
				t.Fatalf("a %s must not create collections", role)
			}
		}
		setRole("custom") // und zurück, die Berechtigungen werden neu gesetzt und bleiben nicht hängen
		if code, _ := createCollection(); code != 200 {
			t.Fatalf("custom after manager/user: %d", code)
		}
	})

	t.Run("role change and removal", func(t *testing.T) {
		s.expect(200, "POST", "/v1/sync", desired(orgName, map[string]string{member.email: "manager"}))
		role := func() string {
			for _, m := range s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)["members"].([]any) {
				if m := m.(map[string]any); m["email"] == member.email {
					return m["role"].(string)
				}
			}
			return "gone"
		}
		if role() != "manager" {
			t.Fatalf("role is %s", role())
		}
		// Obergrenze für Entfernungen. Ein Request, der mehr als erlaubt entfernen würde, ändert nichts.
		s.expect(422, "POST", "/v1/sync?max_removals=0", desired(orgName, map[string]string{}))
		if role() != "manager" {
			t.Fatal("removal limit did not protect the member")
		}
		s.expect(200, "POST", "/v1/sync", desired(orgName, map[string]string{}))
		if role() != "gone" {
			t.Fatalf("member still there: %s", role())
		}
		// Das API-Konto selbst wird nie entfernt.
		if got := s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)["members"].([]any); len(got) != 1 {
			t.Fatalf("expected only the owner, got %v", got)
		}
	})

	t.Run("a revoked member survives every sync, and org names ignore letter case", func(t *testing.T) {
		if memberStatus != "accepted" {
			t.Skip("member was not confirmed")
		}
		// Das Mitglied wurde im vorigen Schritt entfernt. Einladen, bestätigen, dann sperren.
		s.expect(200, "POST", "/v1/sync", desired(orgName, map[string]string{member.email: "user"}))
		s.expect(200, "POST", "/v1/confirm", map[string][]string{"emails": {member.email}})

		var memberID string
		for _, m := range s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)["members"].([]any) {
			if m := m.(map[string]any); m["email"] == member.email {
				memberID = m["id"].(string)
			}
		}
		if memberID == "" {
			t.Fatal("member not found")
		}
		req, _ := http.NewRequest("PUT", vwURL+"/api/organizations/"+orgID+"/users/"+memberID+"/revoke", nil)
		req.Header.Set("Authorization", "Bearer "+admin.passwordToken(t))
		if code, body := do(t, req); code != 200 {
			t.Fatalf("revoke: %d %s", code, body)
		}
		statusOf := func() string {
			for _, m := range s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)["members"].([]any) {
				if m := m.(map[string]any); m["email"] == member.email {
					return m["status"].(string)
				}
			}
			return "gone"
		}
		if got := statusOf(); got != "revoked" {
			t.Fatalf("expected revoked, got %s", got)
		}

		// Ein leerer Soll-Zustand entfernt alle Mitglieder, aber keines, das ein Admin nur gesperrt hat.
		out := s.expect(200, "POST", "/v1/sync", desired(orgName, map[string]string{}))
		if got := statusOf(); got != "revoked" {
			t.Fatalf("a sync removed the revoked member: %s", got)
		}
		if !strings.Contains(fmt.Sprint(out), "is revoked") {
			t.Fatalf("the skipped member is not reported: %v", out)
		}

		// Der Export lässt gesperrte Mitglieder weg, und das Zurückschicken darf sie nicht entfernen.
		exp := s.expect(200, "GET", "/v1/export", nil)
		if strings.Contains(fmt.Sprint(exp["desired"]), member.email) {
			t.Fatalf("revoked member in the exported desired state: %v", exp["desired"])
		}
		s.expect(200, "POST", "/v1/sync", exp["desired"])
		if got := statusOf(); got != "revoked" {
			t.Fatalf("syncing the export removed the revoked member: %s", got)
		}

		// Org-Namen passen ohne Beachtung der Groß- und Kleinschreibung.
		s.expect(200, "GET", "/v1/orgs/"+url.PathEscape(strings.ToLower(orgName))+"/members", nil)
		s.expect(200, "POST", "/v1/sync?dry_run=true", desired(strings.ToUpper(orgName), map[string]string{}))
	})

	t.Run("a member invited before registering is confirmed after registering", func(t *testing.T) {
		// Ohne Mailversand nimmt niemand eine Einladung an. Wer sich noch nicht registriert hat, bleibt
		// "invited" und hat keine Schlüssel, confirm kann also für niemanden verschlüsseln. Die Registrierung
		// macht aus der Einladung "accepted", und der nächste confirm-Aufruf erledigt den Rest.
		late := newAccount(t, pbkdf2Params)
		statusOf := func() string {
			for _, m := range s.expect(200, "GET", "/v1/orgs/"+orgName+"/members", nil)["members"].([]any) {
				if m := m.(map[string]any); m["email"] == late.email {
					return m["status"].(string)
				}
			}
			return "gone"
		}
		confirmBody := map[string][]string{"emails": {late.email}}
		listed := func(out map[string]any, field string) bool {
			orgs := out["orgs"].([]any)
			return len(orgs) == 1 && strings.Contains(fmt.Sprint(orgs[0].(map[string]any)[field]), late.email)
		}

		s.expect(200, "POST", "/v1/sync?no_remove=true", desired(orgName, map[string]string{late.email: "user"}))
		if got := statusOf(); got != "invited" {
			t.Fatalf("an unregistered person must stay invited, got %s", got)
		}

		out := s.expect(200, "POST", "/v1/confirm?dry_run=true", confirmBody)
		if !listed(out, "waiting") || listed(out, "pending") {
			t.Fatalf("an unregistered person must be reported as waiting, not pending: %v", out)
		}
		out = s.expect(200, "POST", "/v1/confirm", confirmBody)
		if out["failures"] != float64(0) || statusOf() != "invited" {
			t.Fatalf("confirming before registration must change nothing and fail nowhere: %v", out)
		}

		late.signUp(t)
		if got := statusOf(); got != "accepted" {
			t.Fatalf("registering must turn the invitation into accepted, got %s", got)
		}
		out = s.expect(200, "POST", "/v1/confirm", confirmBody)
		if out["failures"] != float64(0) || statusOf() != "confirmed" {
			t.Fatalf("%v", out)
		}

		// Das neue Mitglied besitzt den Organisations-Schlüssel.
		var ownerSync, lateSync struct {
			Profile struct{ Organizations []struct{ Key string } }
		}
		admin.get(t, admin.passwordToken(t), "/api/sync", &ownerSync)
		late.get(t, late.passwordToken(t), "/api/sync", &lateSync)
		ownerKey, _ := crypto.DecryptAsymmetric(ownerSync.Profile.Organizations[0].Key, admin.priv)
		lateKey, err := crypto.DecryptAsymmetric(lateSync.Profile.Organizations[0].Key, late.priv)
		if err != nil || !bytes.Equal(ownerKey, lateKey) {
			t.Fatalf("the member invited first got a wrong key: %v", err)
		}
	})

	t.Run("argon2id account works with a real client and as API account", func(t *testing.T) {
		b := newBW(t)
		if b == nil {
			t.Skip("bw not installed")
		}
		argon := register(t, crypto.KDFParams{Type: crypto.KDFArgon2id, Iterations: 3, MemoryMiB: 64, Parallelism: 4})
		// bw leitet den Schlüssel mit einer eigenen Argon2id-Implementierung ab. Wiche unsere ab, schlüge
		// dieser Login fehl.
		b.login(argon)

		cid, secret := argon.apiKey(t)
		c := vaultwarden.New(http.DefaultClient, vwURL, vaultwarden.Credentials{ClientID: cid, ClientSecret: secret, MasterPassword: argon.password})
		if _, err := c.Vault(context.Background()); err != nil {
			t.Fatalf("service cannot unlock an Argon2id account: %v", err)
		}
	})
}
