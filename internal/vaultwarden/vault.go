package vaultwarden

import (
	"context"
	"errors"
	"fmt"

	"vwsync-api/internal/crypto"
)

// ErrNoMasterPassword means the service was started without VW_MASTER_PASSWORD, so it cannot confirm members.
var ErrNoMasterPassword = errors.New("confirm is not configured: VW_MASTER_PASSWORD is not set")

// Vault unlocks the account's keys on first use and keeps them in memory afterwards.
// The unlock is lazy because PBKDF2 with 600k rounds is expensive and only confirm needs it.
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
