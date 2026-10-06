package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
)

// KeyVault holds the unlocked RSA private key of the API account in memory.
// The key never leaves this type and is never written anywhere.
type KeyVault struct {
	priv *rsa.PrivateKey
}

// Unlock derives the keys from the master password and decrypts the account's private key.
// encUserKey and encPrivateKey come from the API-key login response.
func Unlock(encUserKey, encPrivateKey, masterPassword, email string, kdf KDFParams) (*KeyVault, error) {
	masterKey, err := DeriveMasterKey(masterPassword, email, kdf)
	if err != nil {
		return nil, err
	}
	stretched, err := StretchMasterKey(masterKey)
	if err != nil {
		return nil, err
	}
	// A wrong master password fails here, at the MAC check.
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

// OrganizationKey decrypts an organization's key (the "key" field from /api/accounts/profile).
func (v *KeyVault) OrganizationKey(encryptedOrgKey string) ([]byte, error) {
	return DecryptAsymmetric(encryptedOrgKey, v.priv)
}

// PublicKeyB64 is the account's RSA public key as base64 DER/SPKI, the format the API uses.
// It is derived from the private key, so it is never stale.
func (v *KeyVault) PublicKeyB64() (string, error) {
	der, err := x509.MarshalPKIXPublicKey(&v.priv.PublicKey)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
