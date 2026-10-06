package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// NewOrg is the key material the client must generate when it creates an organization.
// The server never sees the organization key in the clear.
type NewOrg struct {
	// Key is the organization key, RSA-encrypted for the creating account.
	Key string
	// CollectionName is the first collection's name, encrypted with the organization key.
	CollectionName string
	// PublicKey and EncryptedPrivateKey are the organization's own RSA key pair
	// (SPKI base64, and PKCS#8 encrypted with the organization key).
	PublicKey           string
	EncryptedPrivateKey string
}

// NewOrganizationKeys generates a fresh organization key and key pair for the account that owns
// the given public key (base64 DER/SPKI).
func NewOrganizationKeys(collectionName, ownerPublicKeyB64 string) (NewOrg, error) {
	orgKey := make([]byte, 64) // 32 bytes AES-256 + 32 bytes HMAC
	if _, err := rand.Read(orgKey); err != nil {
		return NewOrg{}, err
	}
	key, err := EncryptAsymmetric(orgKey, ownerPublicKeyB64)
	if err != nil {
		return NewOrg{}, err
	}
	collection, err := EncryptSymmetric([]byte(collectionName), orgKey)
	if err != nil {
		return NewOrg{}, err
	}

	pair, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return NewOrg{}, fmt.Errorf("generating organization key pair: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(pair)
	if err != nil {
		return NewOrg{}, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&pair.PublicKey)
	if err != nil {
		return NewOrg{}, err
	}
	encPriv, err := EncryptSymmetric(privDER, orgKey)
	if err != nil {
		return NewOrg{}, err
	}
	return NewOrg{
		Key:                 key,
		CollectionName:      collection,
		PublicKey:           base64.StdEncoding.EncodeToString(pubDER),
		EncryptedPrivateKey: encPriv,
	}, nil
}
