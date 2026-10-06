package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// KeyVault hält den entsperrten privaten RSA-Schlüssel des API-Kontos im Speicher.
// Der Schlüssel verlässt diesen Typ nie und wird nirgends gespeichert.
type KeyVault struct {
	priv *rsa.PrivateKey
}

// Unlock leitet die Schlüssel aus dem Master-Passwort ab und entschlüsselt den privaten Schlüssel
// des Kontos. encUserKey und encPrivateKey stammen aus der Antwort des Logins mit API-Key.
func Unlock(encUserKey, encPrivateKey, masterPassword, email string, kdf KDFParams) (*KeyVault, error) {
	masterKey, err := DeriveMasterKey(masterPassword, email, kdf)
	if err != nil {
		return nil, err
	}
	stretched, err := StretchMasterKey(masterKey)
	if err != nil {
		return nil, err
	}
	// Ein falsches Master-Passwort scheitert hier, an der MAC-Prüfung.
	userKey, err := DecryptSymmetric(encUserKey, stretched)
	if err != nil {
		return nil, fmt.Errorf("unlocking user key: %w", err)
	}
	der, err := DecryptSymmetric(encPrivateKey, userKey)
	if err != nil {
		return nil, fmt.Errorf("unlocking private key: %w", err)
	}
	priv, err := LoadPrivateKey(der)
	if err != nil {
		return nil, err
	}
	return &KeyVault{priv: priv}, nil
}

// OrganizationKey entschlüsselt den Schlüssel einer Organisation (Feld "key" aus /api/accounts/profile).
func (v *KeyVault) OrganizationKey(encryptedOrgKey string) ([]byte, error) {
	return DecryptAsymmetric(encryptedOrgKey, v.priv)
}

// PublicKeyB64 ist der öffentliche RSA-Schlüssel des Kontos als Base64 DER/SPKI, im Format der API.
// Er wird aus dem privaten Schlüssel abgeleitet und ist deshalb immer aktuell.
func (v *KeyVault) PublicKeyB64() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&v.priv.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
