package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"vwsync-api/internal/auth"
	"vwsync-api/internal/model"
	"vwsync-api/internal/reconcile"
)

// testKey ist der Zugangsschlüssel, den der Testdienst akzeptiert.
const testKey = "vwsk_" + "T3stKeyT3stKeyT3stKeyT3stKeyT3stKeyT3stKey1"

type fakeDir struct {
	mu       sync.Mutex
	orgs     []model.Organization
	members  map[string][]model.Member
	writes   []string
	noVault  bool
	block    chan struct{} // wenn gesetzt, wartet Invite darauf
	started  chan struct{}
	failMail string
	panicOn  bool // AdminOrganizations löst einen Panic aus, für den Test des Recover-Handlers
}

func (f *fakeDir) SelfEmail(context.Context) (string, error) { return "me@x.io", nil }
func (f *fakeDir) Profile(context.Context) (model.Profile, error) {
	return model.Profile{Email: "me@x.io", Orgs: f.orgs}, nil
}
func (f *fakeDir) AdminOrganizations(context.Context) ([]model.Organization, error) {
	if f.panicOn {
		panic("boom in test")
	}
	return f.orgs, nil
}
func (f *fakeDir) OrgUsers(_ context.Context, id string) ([]model.Member, error) {
	return f.members[id], nil
}
func (f *fakeDir) record(s string) {
	f.mu.Lock()
	f.writes = append(f.writes, s)
	f.mu.Unlock()
}
func (f *fakeDir) Invite(_ context.Context, org, email string, r model.Role) error {
	if f.block != nil {
		close(f.started)
		<-f.block
	}
	if email == f.failMail {
		return errors.New("boom")
	}
	f.record("invite " + email + " " + r.String())
	return nil
}
func (f *fakeDir) ChangeRole(_ context.Context, org, id string, r model.Role) error {
	f.record("role " + id + " " + r.String())
	return nil
}
func (f *fakeDir) Remove(_ context.Context, org, id string) error {
	f.record("remove " + id)
	return nil
}
func (f *fakeDir) Confirm(_ context.Context, org string, m model.Member, key []byte) error {
	f.record("confirm " + m.Email + " " + string(key))
	return nil
}

type fakeKeys struct{}

func (fakeKeys) OrganizationKey(string) ([]byte, error) { return []byte("orgkey"), nil }

func (f *fakeDir) Vault(context.Context) (reconcile.OrgKeys, error) {
	if f.noVault {
		return nil, errNoVault
	}
	return fakeKeys{}, nil
}

var errNoVault = errors.New("confirm is not configured")

func newDir() *fakeDir {
	return &fakeDir{
		orgs: []model.Organization{{ID: "o1", Name: "Team"}},
		members: map[string][]model.Member{"o1": {
			{ID: "m1", Email: "keep@x.io", Role: model.User, Status: model.Confirmed},
			{ID: "m2", Email: "gone@x.io", Role: model.User, Status: model.Confirmed},
			{ID: "m3", Email: "wait@x.io", Role: model.User, Status: model.Accepted, UserID: "u3"},
			{ID: "m4", Email: "other@x.io", Role: model.User, Status: model.Accepted, UserID: "u4"},
		}},
	}
}

type env struct {
	h   http.Handler
	dir *fakeDir
}

func newEnv(t *testing.T, dir *fakeDir) env {
	t.Helper()
	return newEnvLog(t, dir, io.Discard)
}

// newEnvLog ist newEnv mit dem Log des Dienstes in w, für Tests, die das Log prüfen.
func newEnvLog(t *testing.T, dir *fakeDir, w io.Writer) env {
	t.Helper()
	a, err := auth.ParseHashes(auth.HashKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	h := New(Deps{Auth: a, Dir: dir, Log: slog.New(slog.NewTextHandler(w, nil)), TrustProxy: true})
	return env{h, dir}
}

func (e env) do(method, path, token, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("X-Real-IP", "10.0.0.1")
	req.RemoteAddr = "127.0.0.1:50000" // nginx auf demselben Host
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// token liefert den Zugangsschlüssel, den jeder Test als Bearer-Token sendet.
func (e env) token(t *testing.T) string {
	t.Helper()
	return testKey
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("%v: %s", err, rec.Body)
	}
	return m
}

func TestHealthzNeedsNoAuth(t *testing.T) {
	if rec := newEnv(t, newDir()).do("GET", "/healthz", "", ""); rec.Code != 200 {
		t.Fatal(rec.Code)
	}
}

func TestEveryV1RouteRequiresToken(t *testing.T) {
	e := newEnv(t, newDir())
	for _, r := range [][2]string{{"GET", "/v1/orgs"}, {"GET", "/v1/orgs/Team/members"}, {"GET", "/v1/export"}, {"POST", "/v1/sync?dry_run=true"}, {"POST", "/v1/confirm?dry_run=true"}} {
		if rec := e.do(r[0], r[1], "", "{}"); rec.Code != 401 || rec.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("%v without token: %d", r, rec.Code)
		}
		if rec := e.do(r[0], r[1], "garbage", "{}"); rec.Code != 401 {
			t.Errorf("%v with garbage token: %d", r, rec.Code)
		}
	}
}

func TestSyncDryRunWritesNothing(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	body := `{"orgs":{"Team":{"members":{"keep@x.io":"user","new@x.io":"admin","wait@x.io":"user","other@x.io":"user"}}}}`
	rec := e.do("POST", "/v1/sync?dry_run=true", tok, body)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	out := decode(t, rec)
	if out["dry_run"] != true || len(e.dir.writes) != 0 {
		t.Fatalf("dry run wrote: %v", e.dir.writes)
	}
	if !strings.Contains(rec.Body.String(), `"new@x.io"`) || !strings.Contains(rec.Body.String(), `"gone@x.io"`) {
		t.Fatalf("plan missing changes: %s", rec.Body)
	}
}

func TestSyncExecutesByDefault(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	body := `{"orgs":{"o1":{"members":{"keep@x.io":"admin","new@x.io":"user","wait@x.io":"user","other@x.io":"user"}}}}`
	rec := e.do("POST", "/v1/sync", tok, body)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	want := []string{"invite new@x.io user", "role m1 admin", "remove m2"}
	if strings.Join(sortedCopy(e.dir.writes), "|") != strings.Join(sortedCopy(want), "|") {
		t.Fatalf("writes: %v", e.dir.writes)
	}
}

func sortedCopy(in []string) []string {
	out := append([]string{}, in...)
	for i := range out {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

func TestSyncPartialFailureIs207AndContinues(t *testing.T) {
	dir := newDir()
	dir.failMail = "bad@x.io"
	e := newEnv(t, dir)
	body := `{"orgs":{"Team":{"members":{"keep@x.io":"user","gone@x.io":"user","wait@x.io":"user","other@x.io":"user","bad@x.io":"user","good@x.io":"user"}}}}`
	rec := e.do("POST", "/v1/sync", e.token(t), body)
	if rec.Code != 207 || decode(t, rec)["failures"] != float64(1) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(dir.writes) != 1 || dir.writes[0] != "invite good@x.io user" {
		t.Fatalf("a failure must not stop the other changes: %v", dir.writes)
	}
}

func TestRemovalLimitBlocksBeforeAnyChange(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	body := `{"orgs":{"Team":{"members":{"new@x.io":"user"}}}}`
	rec := e.do("POST", "/v1/sync?max_removals=2", tok, body)
	if rec.Code != 422 || len(e.dir.writes) != 0 {
		t.Fatalf("%d writes=%v", rec.Code, e.dir.writes)
	}
	if rec := e.do("POST", "/v1/sync?no_remove=true&max_removals=0", tok, body); rec.Code != 200 {
		t.Fatalf("no_remove must bypass the limit: %d %s", rec.Code, rec.Body)
	}
	for _, w := range e.dir.writes {
		if strings.HasPrefix(w, "remove") {
			t.Fatalf("removed although no_remove=true: %v", e.dir.writes)
		}
	}
}

func TestSyncValidatesInput(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	cases := map[string]struct {
		path, body string
		code       int
	}{
		"typo in field":    {"/v1/sync", `{"orgs":{"Team":{"membres":{}}}}`, 400},
		"bad json":         {"/v1/sync", `{`, 400},
		"unknown role":     {"/v1/sync", `{"orgs":{"Team":{"members":{"a@x.io":"god"}}}}`, 400},
		"unknown2 role":    {"/v1/sync", `{"orgs":{"Team":{"members":{"a@x.io":"unknown"}}}}`, 400},
		"bad email":        {"/v1/sync", `{"orgs":{"Team":{"members":{"nope":"user"}}}}`, 422},
		"unknown org":      {"/v1/sync", `{"orgs":{"Nope":{"members":{}}}}`, 404},
		"bad dry_run flag": {"/v1/sync?dry_run=maybe", `{}`, 400},
		"bad limit":        {"/v1/sync?max_removals=-1", `{}`, 400},
		"trailing garbage": {"/v1/sync", `{} {}`, 400},
	}
	for name, c := range cases {
		if rec := e.do("POST", c.path, tok, c.body); rec.Code != c.code {
			t.Errorf("%s: %d (want %d) %s", name, rec.Code, c.code, rec.Body)
		}
	}
	if len(e.dir.writes) != 0 {
		t.Fatalf("invalid input caused writes: %v", e.dir.writes)
	}
}

func TestConfirmNeedsAllowlistOrAll(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	if rec := e.do("POST", "/v1/confirm", tok, ""); rec.Code != 400 {
		t.Fatalf("%d", rec.Code)
	}
	if rec := e.do("POST", "/v1/confirm?all=true", tok, `{"emails":["wait@x.io"]}`); rec.Code != 400 {
		t.Fatalf("both emails and all: %d", rec.Code)
	}
	if len(e.dir.writes) != 0 {
		t.Fatalf("%v", e.dir.writes)
	}
}

func TestConfirmOnlyAllowlistedAndDryRunLists(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	dry := e.do("POST", "/v1/confirm?dry_run=true", tok, `{"emails":["WAIT@x.io"]}`)
	if dry.Code != 200 || len(e.dir.writes) != 0 || !strings.Contains(dry.Body.String(), "wait@x.io") || strings.Contains(dry.Body.String(), "other@x.io") {
		t.Fatalf("%d %s writes=%v", dry.Code, dry.Body, e.dir.writes)
	}
	rec := e.do("POST", "/v1/confirm", tok, `{"emails":["wait@x.io"]}`)
	if rec.Code != 200 || len(e.dir.writes) != 1 || e.dir.writes[0] != "confirm wait@x.io orgkey" {
		t.Fatalf("%d %s writes=%v", rec.Code, rec.Body, e.dir.writes)
	}
}

func TestConfirmAll(t *testing.T) {
	e := newEnv(t, newDir())
	rec := e.do("POST", "/v1/confirm?all=true", e.token(t), "")
	if rec.Code != 200 || len(e.dir.writes) != 2 {
		t.Fatalf("%d %s %v", rec.Code, rec.Body, e.dir.writes)
	}
}

func TestConfirmWithoutMasterPasswordIs503ButDryRunWorks(t *testing.T) {
	dir := newDir()
	dir.noVault = true
	e := newEnv(t, dir)
	tok := e.token(t)
	if rec := e.do("POST", "/v1/confirm?dry_run=true&all=true", tok, ""); rec.Code != 200 {
		t.Fatalf("dry run needs no master password: %d %s", rec.Code, rec.Body)
	}
	rec := e.do("POST", "/v1/confirm?all=true", tok, "")
	if rec.Code == 200 || len(dir.writes) != 0 {
		t.Fatalf("%d writes=%v", rec.Code, dir.writes)
	}
}

func TestSecondWriteWhileOneRunsGets409(t *testing.T) {
	dir := newDir()
	dir.block, dir.started = make(chan struct{}), make(chan struct{})
	e := newEnv(t, dir)
	tok := e.token(t)
	body := `{"orgs":{"Team":{"members":{"keep@x.io":"user","gone@x.io":"user","wait@x.io":"user","other@x.io":"user","new@x.io":"user"}}}}`

	done := make(chan int)
	go func() { done <- e.do("POST", "/v1/sync", tok, body).Code }()
	<-dir.started
	if rec := e.do("POST", "/v1/sync", tok, body); rec.Code != 409 {
		t.Fatalf("second writer: %d", rec.Code)
	}
	if rec := e.do("POST", "/v1/sync?dry_run=true", tok, body); rec.Code != 200 {
		t.Fatalf("a dry run must not be blocked: %d", rec.Code)
	}
	close(dir.block)
	if code := <-done; code != 200 {
		t.Fatalf("first writer: %d", code)
	}
}

func TestExportAndMembers(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	rec := e.do("GET", "/v1/orgs/Team/members", tok, "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"status":"accepted"`) || !strings.Contains(rec.Body.String(), `"role":"user"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if rec := e.do("GET", "/v1/orgs/o1/members", tok, ""); rec.Code != 200 {
		t.Fatalf("by id: %d", rec.Code)
	}
	if rec := e.do("GET", "/v1/orgs/Nope/members", tok, ""); rec.Code != 404 {
		t.Fatalf("%d", rec.Code)
	}

	exp := e.do("GET", "/v1/export", tok, "")
	if exp.Code != 200 {
		t.Fatal(exp.Code)
	}
	// Der Teil "desired" muss von /v1/sync unverändert akzeptiert werden und nichts planen.
	var parsed struct {
		Desired json.RawMessage `json:"desired"`
	}
	_ = json.Unmarshal(exp.Body.Bytes(), &parsed)
	round := e.do("POST", "/v1/sync?dry_run=true", tok, string(parsed.Desired))
	if round.Code != 200 || bytes.Contains(round.Body.Bytes(), []byte(`"type"`)) {
		t.Fatalf("export is not a no-op when synced back: %d %s", round.Code, round.Body)
	}
}

func TestTheOldApplyParameterIsRejectedInsteadOfBeingIgnored(t *testing.T) {
	// Wer apply=false sendet, erwartet eine Vorschau. Würde der Parameter ignoriert, liefe der Aufruf
	// stattdessen, deshalb muss er deutlich scheitern.
	e := newEnv(t, newDir())
	tok := e.token(t)
	body := `{"orgs":{"Team":{"members":{"new@x.io":"user"}}}}`
	for _, c := range []struct{ path, body string }{
		{"/v1/sync?apply=false", body},
		{"/v1/sync?apply=true", body},
		{"/v1/confirm?apply=false&all=true", ""},
		{"/v1/orgs?apply=false", `{"name":"Fresh"}`},
	} {
		rec := e.do("POST", c.path, tok, c.body)
		if rec.Code != 400 || !strings.Contains(rec.Body.String(), "dry_run=true") {
			t.Errorf("%s: %d %s", c.path, rec.Code, rec.Body)
		}
	}
	if len(e.dir.writes) != 0 {
		t.Fatalf("a rejected call must not write: %v", e.dir.writes)
	}
}

func TestEveryWriteEndpointExecutesWithoutAnyParameter(t *testing.T) {
	e := newEnv(t, waitingDir())
	tok := e.token(t)
	if rec := e.do("POST", "/v1/sync?no_remove=true", tok, `{"orgs":{"Team":{"members":{"new@x.io":"user"}}}}`); rec.Code != 200 {
		t.Fatalf("sync: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/v1/confirm", tok, `{"emails":["ready@x.io"]}`); rec.Code != 200 {
		t.Fatalf("confirm: %d %s", rec.Code, rec.Body)
	}
	if rec := e.do("POST", "/v1/orgs", tok, `{"name":"Fresh"}`); rec.Code != 201 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(e.dir.writes) != 3 {
		t.Fatalf("expected an invite, a confirm and a created org, got %v", e.dir.writes)
	}
}
