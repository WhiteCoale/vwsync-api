package server

import (
	"context"
	"strings"
	"testing"

	"vwsync-api/internal/model"
)

func (f *fakeDir) CreateOrganization(_ context.Context, name, billingEmail string) (model.Organization, error) {
	if f.noVault {
		return model.Organization{}, errNoVault
	}
	f.record("create " + name + " billing=" + billingEmail)
	return model.Organization{ID: "new-id", Name: name}, nil
}

func TestCreateOrgDryRunOnlyChecksTheName(t *testing.T) {
	e := newEnv(t, newDir())
	rec := e.do("POST", "/v1/orgs?dry_run=true", e.token(t), `{"name":"Fresh"}`)
	if rec.Code != 200 || decode(t, rec)["dry_run"] != true || len(e.dir.writes) != 0 {
		t.Fatalf("%d %s writes=%v", rec.Code, rec.Body, e.dir.writes)
	}
}

func TestCreateOrgCreatesByDefault(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	rec := e.do("POST", "/v1/orgs", tok, `{"name":"  Fresh  "}`)
	if rec.Code != 201 || !strings.Contains(rec.Body.String(), `"id":"new-id"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Die Rechnungsadresse ist standardmäßig die des API-Kontos.
	if len(e.dir.writes) != 1 || e.dir.writes[0] != "create Fresh billing=me@x.io" {
		t.Fatalf("%v", e.dir.writes)
	}
	rec = e.do("POST", "/v1/orgs", tok, `{"name":"Other","billing_email":"fin@x.io"}`)
	if rec.Code != 201 || e.dir.writes[1] != "create Other billing=fin@x.io" {
		t.Fatalf("%d %v", rec.Code, e.dir.writes)
	}
}

func TestCreateOrgRefusesDuplicateNameEvenOnDryRun(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	for _, path := range []string{"/v1/orgs?dry_run=true", "/v1/orgs"} {
		if rec := e.do("POST", path, tok, `{"name":"team"}`); rec.Code != 409 {
			t.Fatalf("%s: %d %s", path, rec.Code, rec.Body)
		}
	}
	if len(e.dir.writes) != 0 {
		t.Fatalf("%v", e.dir.writes)
	}
}

func TestCreateOrgValidatesInput(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	cases := map[string]struct {
		body string
		code int
	}{
		"empty name":    {`{"name":"   "}`, 422},
		"missing name":  {`{}`, 422},
		"name too long": {`{"name":"` + strings.Repeat("x", 51) + `"}`, 422},
		"bad billing":   {`{"name":"A","billing_email":"nope"}`, 422},
		"unknown field": {`{"name":"A","plan":"gold"}`, 400},
		"not json":      {`name=A`, 400},
	}
	for name, c := range cases {
		if rec := e.do("POST", "/v1/orgs", tok, c.body); rec.Code != c.code {
			t.Errorf("%s: %d (want %d) %s", name, rec.Code, c.code, rec.Body)
		}
	}
	if len(e.dir.writes) != 0 {
		t.Fatalf("%v", e.dir.writes)
	}
}

func TestCreateOrgRequiresToken(t *testing.T) {
	if rec := newEnv(t, newDir()).do("POST", "/v1/orgs", "", `{"name":"X"}`); rec.Code != 401 {
		t.Fatal(rec.Code)
	}
}

func TestCreateOrgWithoutMasterPasswordWritesNothing(t *testing.T) {
	dir := newDir()
	dir.noVault = true
	e := newEnv(t, dir)
	rec := e.do("POST", "/v1/orgs", e.token(t), `{"name":"Fresh"}`)
	if rec.Code == 201 || len(dir.writes) != 0 {
		t.Fatalf("%d %v", rec.Code, dir.writes)
	}
}
