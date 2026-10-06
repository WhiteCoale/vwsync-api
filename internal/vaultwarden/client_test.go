package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"vwsync-api/internal/crypto"
	"vwsync-api/internal/model"
)

type call struct{ method, path, body string }

// fakeVW is a minimal Vaultwarden. handlers maps "METHOD /path" to a JSON answer.
type fakeVW struct {
	calls    []call
	logins   atomic.Int32
	handlers map[string]string
	login    map[string]any
	reject   atomic.Int32 // number of upcoming /api calls to answer with 401
}

func (f *fakeVW) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.calls = append(f.calls, call{r.Method, r.URL.RequestURI(), string(b)})
	if r.URL.Path == "/identity/connect/token" {
		f.logins.Add(1)
		form, _ := url.ParseQuery(string(b))
		if form.Get("client_id") != "user.1" || form.Get("client_secret") != "s3cret" {
			http.Error(w, `{"error":"invalid_client"}`, 400)
			return
		}
		_ = json.NewEncoder(w).Encode(f.login)
		return
	}
	if r.Header.Get("Authorization") != "Bearer tok" || f.reject.Add(-1) >= 0 {
		http.Error(w, "unauthorized", 401)
		return
	}
	if h, ok := f.handlers[r.Method+" "+r.URL.Path]; ok {
		_, _ = w.Write([]byte(h))
		return
	}
	http.Error(w, "no handler", 404)
}

func newFake(t *testing.T, creds Credentials) (*Client, *fakeVW) {
	f := &fakeVW{handlers: map[string]string{}, login: map[string]any{
		"access_token": "tok", "expires_in": 7200, "Key": "K", "PrivateKey": "P",
		"Kdf": 0, "KdfIterations": 600000,
	}}
	ts := httptest.NewServer(f)
	t.Cleanup(ts.Close)
	return New(ts.Client(), ts.URL, creds), f
}

var good = Credentials{ClientID: "user.1", ClientSecret: "s3cret"}

func TestLoginCachesTokenAndReadsKeyMaterial(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/accounts/profile"] = `{"email":"Admin@X.io"}`
	for i := 0; i < 3; i++ {
		if email, err := c.SelfEmail(context.Background()); err != nil || email != "admin@x.io" {
			t.Fatal(email, err)
		}
	}
	if f.logins.Load() != 1 {
		t.Fatalf("logged in %d times", f.logins.Load())
	}
	ld, _ := c.Login(context.Background())
	if ld.EncUserKey != "K" || ld.EncPrivateKey != "P" || ld.KDF.Iterations != 600000 {
		t.Fatalf("%+v", ld)
	}
}

func TestLoginAcceptsLowerCaseKeyFields(t *testing.T) {
	c, f := newFake(t, good)
	f.login = map[string]any{"access_token": "tok", "expires_in": 7200, "key": "k2", "privateKey": "p2", "kdf": 1, "kdfIterations": 3, "kdfMemory": 64, "kdfParallelism": 4}
	ld, err := c.Login(context.Background())
	if err != nil || ld.EncUserKey != "k2" || ld.EncPrivateKey != "p2" || ld.KDF.Type != 1 || ld.KDF.MemoryMiB != 64 || ld.KDF.Parallelism != 4 {
		t.Fatalf("%+v %v", ld, err)
	}
}

func TestWrongCredentialsGiveAPIErrorWithoutSecret(t *testing.T) {
	c, _ := newFake(t, Credentials{ClientID: "user.1", ClientSecret: "wrong-secret"})
	_, err := c.Login(context.Background())
	if err == nil || strings.Contains(err.Error(), "wrong-secret") {
		t.Fatalf("%v", err)
	}
}

func TestExpiredTokenIsRefreshedOnce(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/accounts/profile"] = `{"email":"a@x.io"}`
	f.reject.Store(1)
	if _, err := c.SelfEmail(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins: %d", f.logins.Load())
	}
}

func TestAdminOrganizationsFilters(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/accounts/profile"] = `{"organizations":[
	 {"id":"1","name":"owner","key":"k","type":0,"status":2,"enabled":true},
	 {"id":"2","name":"admin","type":1,"status":2},
	 {"id":"3","name":"plain user","type":2,"status":2,"enabled":true},
	 {"id":"4","name":"unconfirmed","type":1,"status":1,"enabled":true},
	 {"id":"5","name":"disabled","type":0,"status":2,"enabled":false}]}`
	orgs, err := c.AdminOrganizations(context.Background())
	if err != nil || len(orgs) != 2 || orgs[0].ID != "1" || orgs[1].ID != "2" || orgs[0].EncryptedKey != "k" {
		t.Fatalf("%+v %v", orgs, err)
	}
}

func TestOrgUsersMapsRoleAndStatus(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/organizations/o1/users"] = `{"data":[
	 {"id":"m1","email":"A@X.io","type":1,"status":2,"userId":"u1"},
	 {"id":"m2","email":"b@x.io","type":9,"status":99},
	 {"id":"m3","email":"c@x.io","type":4,"status":2,"permissions":{"createNewCollections":false,"editAnyCollection":false,"deleteAnyCollection":false}},
	 {"id":"m4","email":"d@x.io","type":3,"status":2},
	 {"id":"m5","email":"e@x.io","type":4,"status":2,"permissions":{"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":true}},
	 {"id":"m6","email":"f@x.io","type":4,"status":2,"permissions":{"createNewCollections":true,"editAnyCollection":true,"deleteAnyCollection":false}}]}`
	ms, err := c.OrgUsers(context.Background(), "o1")
	if err != nil || len(ms) != 6 {
		t.Fatal(ms, err)
	}
	if ms[2].Role != model.Manager || ms[3].Role != model.Manager {
		t.Fatalf("Vaultwarden reports a manager as type 4; both 3 and 4 must read as manager: %+v %+v", ms[2], ms[3])
	}
	if ms[0].Email != "a@x.io" || ms[0].Role != model.Admin || ms[0].Status != model.Confirmed || ms[0].UserID != "u1" {
		t.Fatalf("%+v", ms[0])
	}
	if ms[1].Role != model.Unknown || ms[1].Status != model.Invited {
		t.Fatalf("unknown values must be unknown/invited: %+v", ms[1])
	}
	if ms[4].Role != model.Custom {
		t.Fatalf("type 4 with all three collection permissions is custom: %+v", ms[4])
	}
	if ms[5].Role != model.Manager {
		t.Fatalf("a partial permission set is not manage-all-collections: %+v", ms[5])
	}
}

func TestChangeRoleKeepsCollections(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/organizations/o1/users/m1"] = `{"accessAll":false,"collections":[{"id":"c1","readOnly":true}],"groups":["g1"]}`
	f.handlers["PUT /api/organizations/o1/users/m1"] = `{}`
	if err := c.ChangeRole(context.Background(), "o1", "m1", model.Admin); err != nil {
		t.Fatal(err)
	}
	put := f.calls[len(f.calls)-1]
	if put.method != "PUT" {
		t.Fatalf("last call: %+v", put)
	}
	var body struct {
		Type        int              `json:"type"`
		Collections []map[string]any `json:"collections"`
		Groups      []string         `json:"groups"`
	}
	_ = json.Unmarshal([]byte(put.body), &body)
	if body.Type != 1 || len(body.Collections) != 1 || body.Collections[0]["id"] != "c1" || len(body.Groups) != 1 {
		t.Fatalf("collections lost: %s", put.body)
	}
}

func TestInviteSendsNoCollections(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["POST /api/organizations/o1/users/invite"] = `{}`
	if err := c.Invite(context.Background(), "o1", "n@x.io", model.User); err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.Unmarshal([]byte(f.calls[len(f.calls)-1].body), &body)
	if body["type"] != float64(2) || body["accessAll"] != false || len(body["collections"].([]any)) != 0 {
		t.Fatalf("%v", body)
	}
}

func TestConfirmUsesUserIDForPublicKey(t *testing.T) {
	c, f := newFake(t, good)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	f.handlers["GET /api/users/user-1/public-key"] = `{"publicKey":"` + base64.StdEncoding.EncodeToString(pub) + `"}`
	f.handlers["POST /api/organizations/o1/users/mem-1/confirm"] = `{}`

	orgKey := make([]byte, 64)
	_, _ = rand.Read(orgKey)
	m := model.Member{ID: "mem-1", Email: "n@x.io", UserID: "user-1"}
	if err := c.Confirm(context.Background(), "o1", m, orgKey); err != nil {
		t.Fatal(err)
	}
	var body struct{ Key string }
	_ = json.Unmarshal([]byte(f.calls[len(f.calls)-1].body), &body)
	got, err := crypto.DecryptAsymmetric(body.Key, priv)
	if err != nil || string(got) != string(orgKey) {
		t.Fatalf("confirm did not send the org key encrypted for the member: %v", err)
	}

	if err := c.Confirm(context.Background(), "o1", model.Member{ID: "x"}, orgKey); err == nil {
		t.Fatal("member without user id must not be confirmed")
	}
}

func TestServerErrorMessageHasNoRequestBody(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/organizations/o1/users/m1"] = `{}`
	// no PUT handler -> 404
	err := c.ChangeRole(context.Background(), "o1", "m1", model.Admin)
	var ae *APIError
	if err == nil || !errors.As(err, &ae) || ae.Status != 404 || strings.Contains(err.Error(), "accessAll") {
		t.Fatalf("%v", err)
	}
}

func TestVaultNeedsMasterPassword(t *testing.T) {
	c, _ := newFake(t, good)
	if _, err := c.Vault(context.Background()); err != ErrNoMasterPassword {
		t.Fatalf("%v", err)
	}
}

func TestVaultUnlocksFromLoginDataAndIsCached(t *testing.T) {
	const pw, email = "pw-for-test", "admin@x.io"
	kdf := crypto.KDFParams{Type: 0, Iterations: 5}
	mk, _ := crypto.DeriveMasterKey(pw, email, kdf)
	stretched, _ := crypto.StretchMasterKey(mk)
	userKey := make([]byte, 64)
	_, _ = rand.Read(userKey)
	encUser, _ := crypto.EncryptSymmetric(userKey, stretched)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	encPriv, _ := crypto.EncryptSymmetric(der, userKey)

	c, f := newFake(t, Credentials{ClientID: "user.1", ClientSecret: "s3cret", MasterPassword: pw})
	f.login["Key"], f.login["PrivateKey"], f.login["KdfIterations"] = encUser, encPriv, 5
	f.handlers["GET /api/accounts/profile"] = `{"email":"admin@x.io"}`
	v1, err := c.Vault(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if v2, _ := c.Vault(context.Background()); v1 != v2 {
		t.Fatal("vault must be cached")
	}
}

func TestAdminOrganizationsEmptyIsNotNil(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/accounts/profile"] = `{"organizations":[]}`
	orgs, err := c.AdminOrganizations(context.Background())
	if err != nil || orgs == nil || len(orgs) != 0 {
		t.Fatalf("%#v %v", orgs, err)
	}
}

func lastBody(t *testing.T, f *fakeVW) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal([]byte(f.calls[len(f.calls)-1].body), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

func TestRolesAreSentWithTheRightTypeAndPermissions(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["POST /api/organizations/o1/users/invite"] = `{}`
	f.handlers["GET /api/organizations/o1/users/m1"] = `{"collections":[],"groups":[]}`
	f.handlers["PUT /api/organizations/o1/users/m1"] = `{}`

	cases := []struct {
		role      model.Role
		typ       float64
		accessAll bool
		manageAll bool
	}{
		{model.Owner, 0, true, false},
		{model.Admin, 1, true, false},
		{model.User, 2, false, false},
		{model.Manager, 3, false, false},
		{model.Custom, 4, true, true},
	}
	for _, tc := range cases {
		for _, via := range []string{"invite", "role"} {
			var err error
			if via == "invite" {
				err = c.Invite(context.Background(), "o1", "n@x.io", tc.role)
			} else {
				err = c.ChangeRole(context.Background(), "o1", "m1", tc.role)
			}
			if err != nil {
				t.Fatal(err)
			}
			b := lastBody(t, f)
			perms, hasPerms := b["permissions"].(map[string]any)
			if b["type"] != tc.typ || b["accessAll"] != tc.accessAll || hasPerms != tc.manageAll {
				t.Errorf("%s via %s: %v", tc.role, via, b)
			}
			if tc.manageAll && (perms["createNewCollections"] != true || perms["editAnyCollection"] != true || perms["deleteAnyCollection"] != true) {
				t.Errorf("%s via %s: collection permissions missing: %v", tc.role, via, perms)
			}
			if tc.manageAll && (perms["manageUsers"] != false || perms["manageSso"] != false) {
				t.Errorf("custom must not grant more than collection management: %v", perms)
			}
		}
	}
}
