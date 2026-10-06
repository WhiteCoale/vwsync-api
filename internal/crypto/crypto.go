// Package crypto implements the Bitwarden/Vaultwarden primitives that "confirm" needs.
//
// Key hierarchy:
//
//	master password --PBKDF2/Argon2id--> master key --HKDF-Expand--> stretched key (64 bytes)
//	stretched key   decrypts the user key (64 bytes)
//	user key        decrypts the admin's RSA private key
//	RSA private key decrypts the organization key (64 bytes)
//	organization key is RSA-encrypted with the new member's public key and sent to "confirm"
//
// Symmetric keys are 64 bytes: a 32-byte AES-256 key followed by a 32-byte HMAC key.
// EncString format: "<type>.<base64>|<base64>|...". Type 2 is AES-256-CBC + HMAC-SHA256,
// types 3 to 6 are RSA-OAEP (SHA-256 for 3 and 5, SHA-1 for 4 and 6).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/argon2"
)

// KDF identifiers used by the API.
const (
	KDFPBKDF2   = 0
	KDFArgon2id = 1
)

// KDFParams are the key derivation settings of the account, taken from the login response.
type KDFParams struct {
	Type        int
	Iterations  int
	MemoryMiB   int // Argon2id only
	Parallelism int // Argon2id only
}

// DeriveMasterKey derives the 32-byte master key. The e-mail address is the salt.
func DeriveMasterKey(password, email string, p KDFParams) ([]byte, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	switch p.Type {
	case KDFPBKDF2:
		if p.Iterations < 1 {
			return nil, errors.New("invalid KDF iteration count")
		}
		return pbkdf2.Key(sha256.New, password, []byte(email), p.Iterations, 32)
	case KDFArgon2id:
		if p.Iterations < 1 || p.MemoryMiB < 1 || p.Parallelism < 1 || p.Parallelism > 255 {
			return nil, errors.New("invalid Argon2id parameters")
		}
		// Bitwarden hashes the e-mail with SHA-256 to get a fixed-size salt for Argon2id.
		salt := sha256.Sum256([]byte(email))
		return argon2.IDKey([]byte(password), salt[:], uint32(p.Iterations), uint32(p.MemoryMiB)*1024, uint8(p.Parallelism), 32), nil
	}
	return nil, fmt.Errorf("unsupported KDF type %d", p.Type)
}

// StretchMasterKey expands the master key to 64 bytes (AES key + MAC key).
// Bitwarden clients use HKDF-Expand without Extract; that must stay identical.
func StretchMasterKey(masterKey []byte) ([]byte, error) {
	enc, err := hkdf.Expand(sha256.New, masterKey, "enc", 32)
	if err != nil {
		return nil, err
	}
	mac, err := hkdf.Expand(sha256.New, masterKey, "mac", 32)
	if err != nil {
		return nil, err
	}
	return append(enc, mac...), nil
}

// ErrBadMAC is returned when the MAC check fails, usually because the master password is wrong.
var ErrBadMAC = errors.New("MAC mismatch (wrong master password?)")

// DecryptSymmetric decrypts a type 2 EncString. The MAC is verified before decrypting.
func DecryptSymmetric(encString string, key []byte) ([]byte, error) {
	if len(key) != 64 {
		return nil, errors.New("symmetric key must be 64 bytes")
	}
	typ, payload, err := splitEnc(encString)
	if err != nil {
		return nil, err
	}
	if typ != "2" {
		return nil, fmt.Errorf("unsupported symmetric EncString type %s", typ)
	}
	parts := strings.Split(payload, "|")
	if len(parts) != 3 {
		return nil, errors.New("malformed EncString")
	}
	iv, err1 := base64.StdEncoding.DecodeString(parts[0])
	ct, err2 := base64.StdEncoding.DecodeString(parts[1])
	mac, err3 := base64.StdEncoding.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, errors.New("malformed EncString")
	}

	h := hmac.New(sha256.New, key[32:])
	h.Write(iv)
	h.Write(ct)
	if !hmac.Equal(h.Sum(nil), mac) {
		return nil, ErrBadMAC
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return nil, err
	}
	if len(iv) != aes.BlockSize || len(ct) == 0 || len(ct)%aes.BlockSize != 0 {
		return nil, errors.New("malformed EncString")
	}
	plain := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, ct)

	return unpad(plain)
}

// EncryptSymmetric produces a type 2 EncString. The server never needs it; tests use it to build fixtures.
func EncryptSymmetric(plain, key []byte) (string, error) {
	if len(key) != 64 {
		return "", errors.New("symmetric key must be 64 bytes")
	}
	block, err := aes.NewCipher(key[:32])
	if err != nil {
		return "", err
	}
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return "", err
	}
	pad := aes.BlockSize - len(plain)%aes.BlockSize
	padded := append(append([]byte{}, plain...), make([]byte, pad)...)
	for i := len(plain); i < len(padded); i++ {
		padded[i] = byte(pad)
	}
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)

	h := hmac.New(sha256.New, key[32:])
	h.Write(iv)
	h.Write(ct)
	b64 := base64.StdEncoding.EncodeToString
	return "2." + b64(iv) + "|" + b64(ct) + "|" + b64(h.Sum(nil)), nil
}

// DecryptAsymmetric decrypts an RSA EncString, for example the organization key.
func DecryptAsymmetric(encString string, key *rsa.PrivateKey) ([]byte, error) {
	typ, payload, err := splitEnc(encString)
	if err != nil {
		return nil, err
	}
	var h hash.Hash
	switch typ {
	case "3", "5":
		h = sha256.New()
	case "4", "6":
		h = sha1.New()
	default:
		return nil, fmt.Errorf("unsupported RSA EncString type %s", typ)
	}
	ct, err := base64.StdEncoding.DecodeString(strings.SplitN(payload, "|", 2)[0])
	if err != nil {
		return nil, errors.New("malformed EncString")
	}
	plain, err := rsa.DecryptOAEP(h, nil, key, ct, nil)
	if err != nil {
		return nil, errors.New("RSA decryption failed")
	}
	return plain, nil
}

// EncryptAsymmetric encrypts data for a member's public key (base64 DER/SPKI, as the API returns it).
// The result is a type 4 EncString (RSA-OAEP with SHA-1), which is what "confirm" expects.
func EncryptAsymmetric(data []byte, publicKeyB64 string) (string, error) {
	der, err := base64.StdEncoding.DecodeString(publicKeyB64)
	if err != nil {
		return "", errors.New("invalid member public key")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return "", errors.New("invalid member public key")
	}
	pub, ok := parsed.(*rsa.PublicKey)
	if !ok {
		return "", errors.New("member public key is not RSA")
	}
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, data, nil)
	if err != nil {
		return "", fmt.Errorf("RSA encryption failed: %w", err)
	}
	return "4." + base64.StdEncoding.EncodeToString(ct), nil
}

// LoadPrivateKey parses an RSA private key in PKCS#8 DER form.
func LoadPrivateKey(pkcs8 []byte) (*rsa.PrivateKey, error) {
	parsed, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, errors.New("invalid private key")
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return key, nil
}

func splitEnc(s string) (typ, rest string, err error) {
	typ, rest, ok := strings.Cut(s, ".")
	if !ok {
		return "", "", errors.New("malformed EncString")
	}
	return typ, rest, nil
}

func unpad(b []byte) ([]byte, error) {
	if len(b) == 0 {
		return nil, errors.New("AES decryption failed")
	}
	n := int(b[len(b)-1])
	if n < 1 || n > aes.BlockSize || n > len(b) {
		return nil, errors.New("AES decryption failed")
	}
	for _, c := range b[len(b)-n:] {
		if int(c) != n {
			return nil, errors.New("AES decryption failed")
		}
	}
	return b[:len(b)-n], nil
}
