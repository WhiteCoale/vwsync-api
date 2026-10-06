package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func TestNewOrganizationKeys(t *testing.T) {
	owner, _ := rsa.GenerateKey(rand.Reader, 2048)
	ownerPub, _ := x509.MarshalPKIXPublicKey(&owner.PublicKey)

	o, err := NewOrganizationKeys("Default collection", base64.StdEncoding.EncodeToString(ownerPub))
	if err != nil {
		t.Fatal(err)
	}
	// Der Owner gewinnt den Org-Schlüssel mit seinem privaten Schlüssel zurück und damit alles andere.
	orgKey, err := DecryptAsymmetric(o.Key, owner)
	if err != nil || len(orgKey) != 64 {
		t.Fatalf("org key: %d bytes, %v", len(orgKey), err)
	}
	if name, err := DecryptSymmetric(o.CollectionName, orgKey); err != nil || string(name) != "Default collection" {
		t.Fatalf("collection name: %q %v", name, err)
	}
	der, err := DecryptSymmetric(o.EncryptedPrivateKey, orgKey)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(der)
	if err != nil {
		t.Fatal(err)
	}
	wantPub, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if o.PublicKey != base64.StdEncoding.EncodeToString(wantPub) {
		t.Fatal("published key does not belong to the encrypted private key")
	}

	// Zwei Organisationen teilen nie Schlüsselmaterial.
	o2, _ := NewOrganizationKeys("c", base64.StdEncoding.EncodeToString(ownerPub))
	if o2.PublicKey == o.PublicKey {
		t.Fatal("key pair reused")
	}
	if _, err := NewOrganizationKeys("c", "not base64!"); err == nil {
		t.Fatal("bad owner key accepted")
	}
}

func TestVaultPublicKeyMatchesPrivateKey(t *testing.T) {
	kdf := KDFParams{Type: KDFPBKDF2, Iterations: 3}
	mk, _ := DeriveMasterKey("pw", "a@b.c", kdf)
	stretched, _ := StretchMasterKey(mk)
	userKey := newKey(t)
	encUser, _ := EncryptSymmetric(userKey, stretched)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	encPriv, _ := EncryptSymmetric(der, userKey)
	v, err := Unlock(encUser, encPriv, "pw", "a@b.c", kdf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := v.PublicKeyB64()
	want, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil || got != base64.StdEncoding.EncodeToString(want) {
		t.Fatal("public key differs", err)
	}
}
