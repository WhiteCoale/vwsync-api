package vaultwarden

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"vwsync-api/internal/crypto"
)

// unlockedClient liefert einen Client, dessen Testserver Login-Daten zu einem bekannten Master-Passwort
// ausgibt.
func unlockedClient(t *testing.T) (*Client, *fakeVW, *rsa.PrivateKey) {
	t.Helper()
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
	return c, f, priv
}

func TestCreateOrganizationSendsKeysOnlyTheOwnerCanOpen(t *testing.T) {
	c, f, owner := unlockedClient(t)
	f.handlers["POST /api/organizations"] = `{"id":"org-new","name":"Fresh"}`

	org, err := c.CreateOrganization(context.Background(), "Fresh", "billing@x.io")
	if err != nil || org.ID != "org-new" || org.Name != "Fresh" {
		t.Fatalf("%+v %v", org, err)
	}
	var body struct {
		Name, BillingEmail, CollectionName, Key string
		PlanType                                int
		Keys                                    struct{ PublicKey, EncryptedPrivateKey string }
	}
	post := f.calls[len(f.calls)-1]
	if post.method != "POST" || post.path != "/api/organizations" {
		t.Fatalf("last call %+v", post)
	}
	if err := json.Unmarshal([]byte(post.body), &body); err != nil {
		t.Fatal(err)
	}
	if body.Name != "Fresh" || body.BillingEmail != "billing@x.io" || body.PlanType != 0 {
		t.Fatalf("%+v", body)
	}
	orgKey, err := crypto.DecryptAsymmetric(body.Key, owner)
	if err != nil || len(orgKey) != 64 {
		t.Fatalf("org key not encrypted for the API account: %v", err)
	}
	if n, err := crypto.DecryptSymmetric(body.CollectionName, orgKey); err != nil || len(n) == 0 {
		t.Fatalf("collection name: %v", err)
	}
	if _, err := crypto.DecryptSymmetric(body.Keys.EncryptedPrivateKey, orgKey); err != nil || body.Keys.PublicKey == "" {
		t.Fatalf("org key pair: %v", err)
	}
	if strings.Contains(post.body, string(orgKey)) {
		t.Fatal("organization key sent in the clear")
	}
	// Die gelieferte Org ist sofort für confirm nutzbar.
	if got, err := crypto.DecryptAsymmetric(org.EncryptedKey, owner); err != nil || string(got) != string(orgKey) {
		t.Fatalf("returned org carries the wrong key: %v", err)
	}
}

func TestCreateOrganizationNeedsMasterPasswordAndSurfacesServerRefusal(t *testing.T) {
	c, _ := newFake(t, good)
	if _, err := c.CreateOrganization(context.Background(), "X", "a@b.c"); !errors.Is(err, ErrNoMasterPassword) {
		t.Fatalf("%v", err)
	}
	c, _, _ = unlockedClient(t) // kein POST-Handler, der Testserver antwortet mit 404
	var ae *APIError
	if _, err := c.CreateOrganization(context.Background(), "X", "a@b.c"); !errors.As(err, &ae) {
		t.Fatalf("%v", err)
	}
}
