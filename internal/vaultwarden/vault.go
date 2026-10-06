package vaultwarden

import (
	"context"
	"errors"
	"fmt"

	"vwsync-api/internal/crypto"
)

// ErrNoMasterPassword bedeutet, dass der Dienst ohne VW_MASTER_PASSWORD gestartet wurde und deshalb
// weder Mitglieder bestätigen noch Organisationen anlegen kann.
var ErrNoMasterPassword = errors.New("confirm is not configured: VW_MASTER_PASSWORD is not set")

// Vault entsperrt die Schlüssel des Kontos beim ersten Gebrauch und hält sie danach im Speicher.
// Das Entsperren geschieht erst bei Bedarf, weil die Schlüsselableitung teuer ist und nur confirm
// und das Anlegen von Organisationen sie brauchen.
func (c *Client) Vault(ctx context.Context) (*crypto.KeyVault, error) {
	if c.creds.MasterPassword == "" {
		return nil, ErrNoMasterPassword
	}
	c.vaultMu.Lock()
	defer c.vaultMu.Unlock()
	if c.vault != nil {
		return c.vault, nil
	}
	login, err := c.Login(ctx)
	if err != nil {
		return nil, err
	}
	switch {
	case login.Problem != "":
		return nil, fmt.Errorf("cannot unlock the account: %s", login.Problem)
	case login.EncUserKey == "" || login.EncPrivateKey == "":
		return nil, errors.New("cannot unlock the account: the login response has no key material")
	}
	email, err := c.SelfEmail(ctx)
	if err != nil {
		return nil, err
	}
	v, err := crypto.Unlock(login.EncUserKey, login.EncPrivateKey, c.creds.MasterPassword, email, login.KDF)
	if err != nil {
		return nil, err
	}
	c.vault = v
	return v, nil
}
