package crypto

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

func TestPBKDF2KnownAnswer(t *testing.T) {
	// PBKDF2-HMAC-SHA256, password "password", salt "salt", 1 iteration (the e-mail is the salt).
	got, err := DeriveMasterKey("password", "  SALT ", KDFParams{Type: KDFPBKDF2, Iterations: 1})
	if err != nil {
		t.Fatal(err)
	}
	if want := "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"; hex.EncodeToString(got) != want {
		t.Fatalf("got %x", got)
	}
}

func TestStretchIsHKDFExpandWithoutExtract(t *testing.T) {
	mk := []byte("0123456789abcdef0123456789abcdef")
	expand := func(info string) []byte {
		h := hmac.New(sha256.New, mk)
		h.Write([]byte(info))
		h.Write([]byte{1})
		return h.Sum(nil)
	}
	got, err := StretchMasterKey(mk)
	if err != nil {
		t.Fatal(err)
	}
	if want := append(expand("enc"), expand("mac")...); string(got) != string(want) {
		t.Fatal("stretched key differs from HKDF-Expand(enc) || HKDF-Expand(mac)")
	}
}

func TestArgon2idIsDeterministicAndDiffersFromPBKDF2(t *testing.T) {
	p := KDFParams{Type: KDFArgon2id, Iterations: 2, MemoryMiB: 1, Parallelism: 1}
	a, err := DeriveMasterKey("pw", "a@example.com", p)
	if err != nil || len(a) != 32 {
		t.Fatal(err, len(a))
	}
	b, _ := DeriveMasterKey("pw", "A@example.com ", p)
	if string(a) != string(b) {
		t.Fatal("e-mail must be normalized")
	}
	if _, err := DeriveMasterKey("pw", "a@example.com", KDFParams{Type: KDFArgon2id, Iterations: 2}); err == nil {
		t.Fatal("missing Argon2id memory must be rejected")
	}
}

func TestUnsupportedKDF(t *testing.T) {
	if _, err := DeriveMasterKey("pw", "a@b.c", KDFParams{Type: 9, Iterations: 1}); err == nil {
		t.Fatal("expected error")
	}
}

func newKey(t *testing.T) []byte {
	t.Helper()
	k := make([]byte, 64)
	if _, err := rand.Read(k); err != nil {
		t.Fatal(err)
	}
	return k
}

func TestSymmetricRoundTrip(t *testing.T) {
	key := newKey(t)
	for _, n := range []int{0, 1, 15, 16, 17, 64} {
		plain := make([]byte, n)
		_, _ = rand.Read(plain)
		enc, err := EncryptSymmetric(plain, key)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecryptSymmetric(enc, key)
		if err != nil || string(got) != string(plain) {
			t.Fatalf("len %d: %v", n, err)
		}
	}
}

func TestSymmetricRejectsWrongKeyAndTampering(t *testing.T) {
	key := newKey(t)
	enc, _ := EncryptSymmetric([]byte("secret"), key)
	if _, err := DecryptSymmetric(enc, newKey(t)); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("wrong key: %v", err)
	}
	parts := strings.Split(strings.TrimPrefix(enc, "2."), "|")
	ct, _ := base64.StdEncoding.DecodeString(parts[1])
	ct[0] ^= 1
	parts[1] = base64.StdEncoding.EncodeToString(ct)
	if _, err := DecryptSymmetric("2."+strings.Join(parts, "|"), key); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("tampered: %v", err)
	}
	for _, bad := range []string{"", "nodot", "2.a|b", "9.a|b|c", "2.!|!|!"} {
		if _, err := DecryptSymmetric(bad, key); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestAsymmetricRoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	orgKey := newKey(t)

	enc, err := EncryptAsymmetric(orgKey, base64.StdEncoding.EncodeToString(pubDER))
	if err != nil || !strings.HasPrefix(enc, "4.") {
		t.Fatal(enc, err)
	}
	got, err := DecryptAsymmetric(enc, priv)
	if err != nil || string(got) != string(orgKey) {
		t.Fatal(err)
	}
	if _, err := DecryptAsymmetric("7.abc", priv); err == nil {
		t.Fatal("unsupported type accepted")
	}
	if _, err := EncryptAsymmetric(orgKey, "not base64!"); err == nil {
		t.Fatal("bad public key accepted")
	}
}

func TestUnlockFullChain(t *testing.T) {
	const password, email = "correct horse", "Admin@Example.com"
	kdf := KDFParams{Type: KDFPBKDF2, Iterations: 10}

	// Build what the server would hand out: user key under the stretched master key,
	// private key under the user key, org key under the account's public key.
	mk, _ := DeriveMasterKey(password, email, kdf)
	stretched, _ := StretchMasterKey(mk)
	userKey := newKey(t)
	encUserKey, _ := EncryptSymmetric(userKey, stretched)
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	der, _ := x509.MarshalPKCS8PrivateKey(priv)
	encPriv, _ := EncryptSymmetric(der, userKey)
	pubDER, _ := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	orgKey := newKey(t)
	encOrgKey, _ := EncryptAsymmetric(orgKey, base64.StdEncoding.EncodeToString(pubDER))

	vault, err := Unlock(encUserKey, encPriv, password, email, kdf)
	if err != nil {
		t.Fatal(err)
	}
	got, err := vault.OrganizationKey(encOrgKey)
	if err != nil || string(got) != string(orgKey) {
		t.Fatal(err)
	}
	if _, err := Unlock(encUserKey, encPriv, "wrong", email, kdf); !errors.Is(err, ErrBadMAC) {
		t.Fatalf("wrong password: %v", err)
	}
}
