package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// NewOrg ist das Schlüsselmaterial, das der Client beim Anlegen einer Organisation erzeugen muss.
// Der Server sieht den Organisations-Schlüssel nie im Klartext.
type NewOrg struct {
	// Key ist der Organisations-Schlüssel, per RSA für das anlegende Konto verschlüsselt.
	Key string
	// CollectionName ist der Name der ersten Sammlung, verschlüsselt mit dem Organisations-Schlüssel.
	CollectionName string
	// PublicKey und EncryptedPrivateKey sind das eigene RSA-Schlüsselpaar der Organisation
	// (SPKI in Base64 und PKCS#8, verschlüsselt mit dem Organisations-Schlüssel).
	PublicKey           string
	EncryptedPrivateKey string
}

// NewOrganizationKeys erzeugt einen neuen Organisations-Schlüssel samt Schlüsselpaar für das Konto,
// dem der übergebene öffentliche Schlüssel (Base64 DER/SPKI) gehört.
func NewOrganizationKeys(collectionName, ownerPublicKeyB64 string) (NewOrg, error) {
	orgKey := make([]byte, 64) // 32 Byte AES-256 und 32 Byte HMAC
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
