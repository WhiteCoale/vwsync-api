// Package crypto bildet die Bausteine von Bitwarden/Vaultwarden nach, die confirm und das Anlegen
// von Organisationen brauchen.
//
// Schlüsselhierarchie:
//
//	Master-Passwort  --PBKDF2/Argon2id--> Master-Key --HKDF-Expand--> gestreckter Key (64 Byte)
//	gestreckter Key  entschlüsselt den User-Key (64 Byte)
//	User-Key         entschlüsselt den privaten RSA-Schlüssel des Admins
//	privater RSA-Key entschlüsselt den Organisations-Schlüssel (64 Byte)
//	Organisations-Schlüssel wird mit dem öffentlichen Schlüssel des neuen Mitglieds verschlüsselt
//	und an confirm gesendet
//
// Symmetrische Schlüssel haben 64 Byte, 32 Byte AES-256-Schlüssel gefolgt von 32 Byte HMAC-Schlüssel.
// Format eines EncStrings: "<Typ>.<Base64>|<Base64>|...". Typ 2 ist AES-256-CBC mit HMAC-SHA256,
// Typ 3 bis 6 sind RSA-OAEP (SHA-256 bei 3 und 5, SHA-1 bei 4 und 6).
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // das Bitwarden-Protokoll schreibt RSA-OAEP mit SHA-1 vor (EncString Typ 4)
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Kennungen der Schlüsselableitung (KDF) in der API.
const (
	KDFPBKDF2   = 0
	KDFArgon2id = 1
)

// Obergrenzen für die Argon2id-Parameter, die der Server liefert. Bitwarden erlaubt höchstens 1024 MiB
// und 16 Threads. Die Grenzen verhindern, dass ein defekter oder bösartiger Server den Speicher des
// Dienstes erschöpft, und machen die Umwandlung nach uint32 und uint8 weiter unten sicher.
const (
	maxArgon2Iterations  = 100
	maxArgon2MemoryMiB   = 4096
	maxArgon2Parallelism = 64
)

// KDFParams sind die Einstellungen der Schlüsselableitung des Kontos aus der Login-Antwort.
type KDFParams struct {
	Type        int
	Iterations  int
	MemoryMiB   int // nur Argon2id
	Parallelism int // nur Argon2id
}

// DeriveMasterKey leitet den 32 Byte langen Master-Key ab. Die E-Mail-Adresse dient als Salt.
func DeriveMasterKey(password, email string, p KDFParams) ([]byte, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	switch p.Type {
	case KDFPBKDF2:
		if p.Iterations < 1 {
			return nil, errors.New("invalid KDF iteration count")
		}
		return pbkdf2.Key(sha256.New, password, []byte(email), p.Iterations, 32)
	case KDFArgon2id:
		if p.Iterations < 1 || p.Iterations > maxArgon2Iterations ||
			p.MemoryMiB < 1 || p.MemoryMiB > maxArgon2MemoryMiB ||
			p.Parallelism < 1 || p.Parallelism > maxArgon2Parallelism {
			return nil, errors.New("invalid Argon2id parameters")
		}
		// Bitwarden hasht die E-Mail mit SHA-256, um für Argon2id ein Salt fester Länge zu erhalten.
		salt := sha256.Sum256([]byte(email))
		return argon2.IDKey([]byte(password), salt[:], uint32(p.Iterations), uint32(p.MemoryMiB)*1024, uint8(p.Parallelism), 32), nil //nolint:gosec // oben begrenzt
	}
	return nil, fmt.Errorf("unsupported KDF type %d", p.Type)
}

// StretchMasterKey streckt den Master-Key auf 64 Byte (AES-Schlüssel und MAC-Schlüssel).
// Bitwarden-Clients nutzen HKDF-Expand ohne Extract. Das muss genau so bleiben.
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

// ErrBadMAC meldet eine fehlgeschlagene MAC-Prüfung, meist wegen eines falschen Master-Passworts.
var ErrBadMAC = errors.New("MAC mismatch (wrong master password?)")

// DecryptSymmetric entschlüsselt einen EncString vom Typ 2. Die MAC wird vor dem Entschlüsseln geprüft.
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

// EncryptSymmetric erzeugt einen EncString vom Typ 2, etwa für den Namen einer neuen Sammlung und in
// Tests für Testdaten.
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

// DecryptAsymmetric entschlüsselt einen RSA-EncString, zum Beispiel den Organisations-Schlüssel.
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
		h = sha1.New() //nolint:gosec // siehe Import
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

// EncryptAsymmetric verschlüsselt Daten für den öffentlichen Schlüssel eines Mitglieds (Base64 DER/SPKI,
// so wie die API ihn liefert). Das Ergebnis ist ein EncString vom Typ 4 (RSA-OAEP mit SHA-1), den
// confirm erwartet.
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
	ct, err := rsa.EncryptOAEP(sha1.New(), rand.Reader, pub, data, nil) //nolint:gosec // siehe Import
	if err != nil {
		return "", fmt.Errorf("RSA encryption failed: %w", err)
	}
	return "4." + base64.StdEncoding.EncodeToString(ct), nil
}

// LoadPrivateKey liest einen privaten RSA-Schlüssel im Format PKCS#8 DER.
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
