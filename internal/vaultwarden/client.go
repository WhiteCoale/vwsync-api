// Package vaultwarden is a small typed client for the Vaultwarden/Bitwarden user API.
//
// It authenticates with a personal API key (OAuth2 client_credentials). The key belongs to a normal
// account that must be owner or admin of the affected organizations. The organization API
// (/api/public) is not used because it can neither change roles nor confirm members.
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"vwsync-api/internal/crypto"
	"vwsync-api/internal/model"
)

// Credentials is the personal API key of the managing account.
type Credentials struct {
	ClientID     string
	ClientSecret string
	// MasterPassword is optional and only needed for Confirm.
	MasterPassword string
}

// APIError is a failed call. It carries the server's answer, never the request body (it may hold secrets).
type APIError struct {
	Method, Path string
	Status       int
	Body         string
}

func (e *APIError) Error() string {
	if e.Status == 0 {
		return fmt.Sprintf("%s %s failed: %s", e.Method, e.Path, e.Body)
	}
	return fmt.Sprintf("%s %s -> %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// LoginData is what "confirm" needs from the token response to unlock the account's keys.
type LoginData struct {
	EncUserKey    string
	EncPrivateKey string
	KDF           crypto.KDFParams
	// Problem is set when the login response had key material in an unexpected shape. It does not
	// break the login, because only confirm and org creation need the keys. Vault reports it.
	Problem string
}

type Client struct {
	http  *http.Client
	base  string
	creds Credentials

	log *slog.Logger // optional, debug output only

	mu      sync.Mutex // guards the session fields below
	token   string
	expires time.Time
	login   LoginData

	vaultMu sync.Mutex
	vault   *crypto.KeyVault
}

func New(httpClient *http.Client, baseURL string, creds Credentials) *Client {
	return &Client{http: httpClient, base: strings.TrimRight(baseURL, "/"), creds: creds}
}

// WithLogger makes the client log every call at debug level: method, path, status and duration.
// Never bodies, headers or tokens.
func (c *Client) WithLogger(l *slog.Logger) *Client {
	c.log = l
	return c
}

// Login returns the key material of the current session, logging in first if needed.
func (c *Client) Login(ctx context.Context) (LoginData, error) {
	if _, err := c.bearer(ctx, false); err != nil {
		return LoginData{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login, nil
}

// Profile reads the API account's address and the organizations it manages with a single request.
// Organizations are limited to those where the account is a confirmed, enabled owner or admin.
func (c *Client) Profile(ctx context.Context) (model.Profile, error) {
	var p struct {
		Email         string `json:"email"`
		Organizations []struct {
			ID      string `json:"id"`
			Name    string `json:"name"`
			Key     string `json:"key"`
			Type    int    `json:"type"`
			Status  int    `json:"status"`
			Enabled *bool  `json:"enabled"`
		} `json:"organizations"`
	}
	if err := c.api(ctx, "GET", "/accounts/profile", nil, &p); err != nil {
		return model.Profile{}, err
	}
	orgs := []model.Organization{} // not nil: an empty list must marshal as [] and not as null
	for _, o := range p.Organizations {
		isAdmin := o.Type == int(model.Owner) || o.Type == int(model.Admin)
		if isAdmin && o.Status == int(model.Confirmed) && (o.Enabled == nil || *o.Enabled) {
			orgs = append(orgs, model.Organization{ID: o.ID, Name: o.Name, EncryptedKey: o.Key})
		}
	}
	return model.Profile{Email: strings.ToLower(p.Email), Orgs: orgs}, nil
}

// SelfEmail is the managing account's address, lower case. The planner never touches this account.
func (c *Client) SelfEmail(ctx context.Context) (string, error) {
	p, err := c.Profile(ctx)
	return p.Email, err
}

// AdminOrganizations lists organizations where the account is a confirmed, enabled owner or admin.
func (c *Client) AdminOrganizations(ctx context.Context) ([]model.Organization, error) {
	p, err := c.Profile(ctx)
	return p.Orgs, err
}

// OrgUsers lists all members of an organization with role and status.
func (c *Client) OrgUsers(ctx context.Context, orgID string) ([]model.Member, error) {
	var r struct {
		Data []struct {
			ID          string `json:"id"`
			Email       string `json:"email"`
			Type        int    `json:"type"`
			Status      int    `json:"status"`
			UserID      string `json:"userId"`
			Permissions struct {
				CreateNewCollections bool `json:"createNewCollections"`
				EditAnyCollection    bool `json:"editAnyCollection"`
				DeleteAnyCollection  bool `json:"deleteAnyCollection"`
			} `json:"permissions"`
		} `json:"data"`
	}
	if err := c.api(ctx, "GET", "/organizations/"+url.PathEscape(orgID)+"/users", nil, &r); err != nil {
		return nil, err
	}
	members := make([]model.Member, 0, len(r.Data))
	for _, m := range r.Data {
		members = append(members, model.Member{
			ID:     m.ID,
			Email:  strings.ToLower(m.Email),
			Role:   model.RoleFromAPI(m.Type, m.Permissions.CreateNewCollections && m.Permissions.EditAnyCollection && m.Permissions.DeleteAnyCollection),
			Status: model.StatusFromAPI(m.Status),
			UserID: m.UserID,
		})
	}
	return members, nil
}

// Invite invites a person by e-mail. No individual collections are granted.
func (c *Client) Invite(ctx context.Context, orgID, email string, role model.Role) error {
	body := roleFields(role)
	body["emails"] = []string{email}
	body["collections"] = []any{}
	body["groups"] = []any{}
	return c.api(ctx, "POST", "/organizations/"+url.PathEscape(orgID)+"/users/invite", body, nil)
}

// ChangeRole changes a member's role. The PUT endpoint REPLACES the collection assignment, so the
// current assignment is read first and sent back unchanged. Sending empty lists would revoke access.
func (c *Client) ChangeRole(ctx context.Context, orgID, memberID string, role model.Role) error {
	path := "/organizations/" + url.PathEscape(orgID) + "/users/" + url.PathEscape(memberID)
	var cur struct {
		Collections []any `json:"collections"`
		Groups      []any `json:"groups"`
	}
	if err := c.api(ctx, "GET", path+"?includeCollections=true", nil, &cur); err != nil {
		return err
	}
	body := roleFields(role)
	body["collections"], body["groups"] = orEmpty(cur.Collections), orEmpty(cur.Groups)
	return c.api(ctx, "PUT", path, body, nil)
}

func orEmpty(l []any) []any {
	if l == nil {
		return []any{}
	}
	return l
}

// roleFields are the request fields that carry a role.
//
// Vaultwarden derives "access all collections" from the role and ignores a client-sent accessAll: it is
// on for owner and admin, and for the custom role when all three collection permissions are set. The
// custom role is sent as type 4, a manager as type 3 (no permissions, so no access to all collections).
func roleFields(role model.Role) map[string]any {
	f := map[string]any{"type": int(role), "accessAll": role == model.Owner || role == model.Admin || role == model.Custom}
	if role == model.Custom {
		f["permissions"] = map[string]bool{
			"createNewCollections":      true,
			"editAnyCollection":         true,
			"deleteAnyCollection":       true,
			"editAssignedCollections":   true,
			"deleteAssignedCollections": true,
			"accessEventLogs":           false,
			"accessImportExport":        false,
			"accessReports":             false,
			"manageGroups":              false,
			"managePolicies":            false,
			"manageSso":                 false,
			"manageUsers":               false,
			"manageResetPassword":       false,
		}
	}
	return f
}

// Remove removes a member, including pending invitations.
func (c *Client) Remove(ctx context.Context, orgID, memberID string) error {
	return c.api(ctx, "DELETE", "/organizations/"+url.PathEscape(orgID)+"/users/"+url.PathEscape(memberID), nil, nil)
}

// Confirm confirms a member whose status is "accepted". The server does not know the organization
// key (end-to-end encryption), so the admin encrypts it with the new member's public key.
// The public key is looked up by USER id, not by membership id.
func (c *Client) Confirm(ctx context.Context, orgID string, m model.Member, orgKey []byte) error {
	if m.UserID == "" {
		return fmt.Errorf("member %s has no user id yet and cannot be confirmed", m.Email)
	}
	var pk struct {
		PublicKey string `json:"publicKey"`
	}
	if err := c.api(ctx, "GET", "/users/"+url.PathEscape(m.UserID)+"/public-key", nil, &pk); err != nil {
		return err
	}
	key, err := crypto.EncryptAsymmetric(orgKey, pk.PublicKey)
	if err != nil {
		return fmt.Errorf("member %s: %w", m.Email, err)
	}
	return c.api(ctx, "POST", "/organizations/"+url.PathEscape(orgID)+"/users/"+url.PathEscape(m.ID)+"/confirm",
		map[string]any{"key": key}, nil)
}

// CreateOrganization creates an organization owned by the API account. Bitwarden is end-to-end
// encrypted, so this client generates the organization key and key pair itself (needs the master
// password, like Confirm). Names are not unique on the server: callers must check for duplicates.
func (c *Client) CreateOrganization(ctx context.Context, name, billingEmail string) (model.Organization, error) {
	vault, err := c.Vault(ctx)
	if err != nil {
		return model.Organization{}, err
	}
	pub, err := vault.PublicKeyB64()
	if err != nil {
		return model.Organization{}, err
	}
	keys, err := crypto.NewOrganizationKeys("Default collection", pub)
	if err != nil {
		return model.Organization{}, err
	}
	var created struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	err = c.api(ctx, "POST", "/organizations", map[string]any{
		"name":           name,
		"billingEmail":   billingEmail,
		"collectionName": keys.CollectionName,
		"key":            keys.Key,
		"keys":           map[string]string{"publicKey": keys.PublicKey, "encryptedPrivateKey": keys.EncryptedPrivateKey},
		"planType":       0, // ignored by Vaultwarden, but the field is required
	}, &created)
	if err != nil {
		return model.Organization{}, err
	}
	if created.ID == "" {
		return model.Organization{}, errors.New("server returned no organization id")
	}
	return model.Organization{ID: created.ID, Name: created.Name, EncryptedKey: keys.Key}, nil
}

// api calls /api{path}. A 401 triggers one fresh login and one retry, because the token may have expired.
func (c *Client) api(ctx context.Context, method, path string, body, out any) error {
	for attempt := 0; ; attempt++ {
		token, err := c.bearer(ctx, attempt > 0)
		if err != nil {
			return err
		}
		err = c.do(ctx, method, "/api"+path, token, body, nil, out)
		var ae *APIError
		if attempt == 0 && errors.As(err, &ae) && ae.Status == http.StatusUnauthorized {
			continue
		}
		return err
	}
}

// bearer returns a valid access token, logging in when none exists, it is about to expire, or force is set.
func (c *Client) bearer(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Now().Before(c.expires) {
		return c.token, nil
	}

	form := url.Values{
		"grant_type":    {"client_credentials"},
		"scope":         {"api"},
		"client_id":     {c.creds.ClientID},
		"client_secret": {c.creds.ClientSecret},
		"deviceType":    {"21"},
		"deviceName":    {"vwsync-api"},
		// Constant per API key so the server does not register a new device on every login.
		"deviceIdentifier": {deviceID(c.creds.ClientID)},
	}
	var r map[string]json.RawMessage
	if err := c.do(ctx, "POST", "/identity/connect/token", "", nil, form, &r); err != nil {
		return "", err
	}
	get := func(name string) json.RawMessage {
		if v, ok := r[name]; ok {
			return v
		}
		return r[strings.ToLower(name[:1])+name[1:]] // some server versions use "key", others "Key"
	}
	problem := ""
	str := func(name string) string {
		var s string
		if raw := get(name); raw != nil {
			if err := json.Unmarshal(raw, &s); err != nil && problem == "" {
				problem = fmt.Sprintf("login field %q is not a string", name)
			}
		}
		return s
	}
	num := func(name string) int {
		var n int
		if raw := get(name); raw != nil {
			if err := json.Unmarshal(raw, &n); err != nil && problem == "" {
				problem = fmt.Sprintf("login field %q is not a number", name)
			}
		}
		return n
	}

	var token string
	if err := json.Unmarshal(r["access_token"], &token); err != nil || token == "" {
		return "", errors.New("login returned no access token")
	}
	expiresIn := num("expires_in")
	if expiresIn < 120 {
		expiresIn = 120
	}
	c.token = token
	c.expires = time.Now().Add(time.Duration(expiresIn-60) * time.Second)
	c.login = LoginData{
		EncUserKey:    str("Key"),
		EncPrivateKey: str("PrivateKey"),
		KDF: crypto.KDFParams{
			Type:        num("Kdf"),
			Iterations:  num("KdfIterations"),
			MemoryMiB:   num("KdfMemory"),
			Parallelism: num("KdfParallelism"),
		},
		Problem: problem,
	}
	return c.token, nil
}

// do performs one HTTP request. HTTP >= 400 and network errors become an *APIError.
func (c *Client) do(ctx context.Context, method, path, token string, jsonBody any, form url.Values, out any) error {
	var body io.Reader
	contentType := ""
	switch {
	case form != nil:
		body, contentType = strings.NewReader(form.Encode()), "application/x-www-form-urlencoded"
	case jsonBody != nil:
		b, err := json.Marshal(jsonBody)
		if err != nil {
			return err
		}
		body, contentType = bytes.NewReader(b), "application/json"
	}
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "vwsync-api")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	start := time.Now()
	resp, err := c.http.Do(req)
	if c.log != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		c.log.Debug("vaultwarden call", "method", method, "path", path, "status", status, "ms", time.Since(start).Milliseconds())
	}
	if err != nil {
		// url.Error repeats the URL only, no body, so it is safe to show.
		return &APIError{Method: method, Path: path, Body: err.Error()}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return &APIError{Method: method, Path: path, Body: err.Error()}
	}
	if resp.StatusCode >= 400 {
		msg := truncate(string(raw), 300)
		return &APIError{Method: method, Path: path, Status: resp.StatusCode, Body: msg}
	}
	if out == nil || len(bytes.TrimSpace(raw)) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &APIError{Method: method, Path: path, Body: "response is not valid JSON"}
	}
	return nil
}

// deviceID derives a stable UUID-shaped device id from the client id. It is only an identifier, not a
// secret, but SHA-256 keeps security scanners quiet.
func deviceID(clientID string) string {
	sum := sha256.Sum256([]byte("vwsync/" + clientID))
	h := hex.EncodeToString(sum[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// truncate shortens s to at most n bytes without cutting a multi-byte character in half.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}
