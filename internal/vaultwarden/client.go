// Package vaultwarden ist ein kleiner, typisierter Client für die Benutzer-API von Vaultwarden/Bitwarden.
//
// Er meldet sich mit einem persönlichen API-Key an (OAuth2 client_credentials). Der Key gehört einem
// normalen Konto, das in den betroffenen Organisationen Owner oder Admin sein muss. Die
// Organisations-API (/api/public) wird nicht genutzt, weil sie weder Rollen ändern noch Mitglieder
// bestätigen kann.
package vaultwarden

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"vwsync-api/internal/crypto"
	"vwsync-api/internal/model"
)

// Credentials ist der persönliche API-Key des verwaltenden Kontos.
type Credentials struct {
	ClientID     string
	ClientSecret string
	// MasterPassword ist optional und nur für Confirm und CreateOrganization nötig.
	MasterPassword string
}

// APIError ist ein fehlgeschlagener Aufruf. Er enthält die Antwort des Servers, nie den Request-Body,
// denn der kann Secrets enthalten.
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

// LoginData ist das, was confirm aus der Token-Antwort braucht, um die Schlüssel des Kontos zu entsperren.
type LoginData struct {
	EncUserKey    string
	EncPrivateKey string
	KDF           crypto.KDFParams
	// Problem ist gesetzt, wenn die Login-Antwort Schlüsselmaterial in unerwarteter Form enthielt. Der
	// Login scheitert daran nicht, weil nur confirm und das Anlegen von Orgs die Schlüssel brauchen.
	// Vault meldet das Problem.
	Problem string
}

type Client struct {
	http  *http.Client
	base  string
	creds Credentials

	log *slog.Logger // optional, nur für Debug-Ausgaben

	mu      sync.Mutex // schützt die Sitzungsfelder darunter
	token   string
	expires time.Time
	login   LoginData

	vaultMu sync.Mutex
	vault   *crypto.KeyVault
}

func New(httpClient *http.Client, baseURL string, creds Credentials) *Client {
	return &Client{http: httpClient, base: strings.TrimRight(baseURL, "/"), creds: creds}
}

// WithLogger lässt den Client jeden Aufruf auf Debug-Level protokollieren, mit Methode, Pfad, Status
// und Dauer. Nie mit Bodies, Headern oder Tokens.
func (c *Client) WithLogger(l *slog.Logger) *Client {
	c.log = l
	return c
}

// Login liefert das Schlüsselmaterial der aktuellen Sitzung und meldet sich vorher an, falls nötig.
func (c *Client) Login(ctx context.Context) (LoginData, error) {
	if _, err := c.bearer(ctx, false); err != nil {
		return LoginData{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.login, nil
}

// Profile liest die Adresse des API-Kontos und die verwalteten Organisationen mit einem einzigen
// Request. Es zählen nur Organisationen, in denen das Konto bestätigter Owner oder Admin ist und die
// aktiv sind.
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
	orgs := []model.Organization{} // nicht nil, eine leere Liste muss als [] serialisiert werden, nicht als null
	for _, o := range p.Organizations {
		isAdmin := o.Type == int(model.Owner) || o.Type == int(model.Admin)
		if isAdmin && o.Status == int(model.Confirmed) && (o.Enabled == nil || *o.Enabled) {
			orgs = append(orgs, model.Organization{ID: o.ID, Name: o.Name, EncryptedKey: o.Key})
		}
	}
	return model.Profile{Email: strings.ToLower(p.Email), Orgs: orgs}, nil
}

// SelfEmail ist die Adresse des verwaltenden Kontos in Kleinbuchstaben. Der Planer fasst dieses Konto
// nie an.
func (c *Client) SelfEmail(ctx context.Context) (string, error) {
	p, err := c.Profile(ctx)
	return p.Email, err
}

// AdminOrganizations listet die aktiven Organisationen, in denen das Konto bestätigter Owner oder Admin ist.
func (c *Client) AdminOrganizations(ctx context.Context) ([]model.Organization, error) {
	p, err := c.Profile(ctx)
	return p.Orgs, err
}

// OrgUsers listet alle Mitglieder einer Organisation mit Rolle und Status.
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

// Invite lädt eine Person per E-Mail ein. Einzelne Sammlungen werden dabei nicht freigegeben.
func (c *Client) Invite(ctx context.Context, orgID, email string, role model.Role) error {
	body := roleFields(role)
	body["emails"] = []string{email}
	body["collections"] = []any{}
	body["groups"] = []any{}
	return c.api(ctx, "POST", "/organizations/"+url.PathEscape(orgID)+"/users/invite", body, nil)
}

// ChangeRole ändert die Rolle eines Mitglieds. Der PUT-Endpunkt ERSETZT die Zuordnung zu Sammlungen.
// Deshalb wird die aktuelle Zuordnung zuerst gelesen und unverändert zurückgesendet. Leere Listen
// würden den Zugriff entziehen.
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

// roleFields sind die Request-Felder, die eine Rolle beschreiben.
//
// Vaultwarden leitet "Zugriff auf alle Sammlungen" aus der Rolle ab und ignoriert ein vom Client
// gesendetes accessAll. Der Zugriff ist an für Owner und Admin sowie für die Rolle custom, wenn alle
// drei Sammlungs-Berechtigungen gesetzt sind. Die Rolle custom wird als Typ 4 gesendet, ein Manager als
// Typ 3 (ohne Berechtigungen, also ohne Zugriff auf alle Sammlungen).
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

// Remove entfernt ein Mitglied, auch eines mit offener Einladung.
func (c *Client) Remove(ctx context.Context, orgID, memberID string) error {
	return c.api(ctx, "DELETE", "/organizations/"+url.PathEscape(orgID)+"/users/"+url.PathEscape(memberID), nil, nil)
}

// Confirm bestätigt ein Mitglied mit Status "accepted". Der Server kennt den Organisations-Schlüssel
// nicht (Ende-zu-Ende-Verschlüsselung), deshalb verschlüsselt ihn der Admin mit dem öffentlichen
// Schlüssel des neuen Mitglieds. Der öffentliche Schlüssel wird über die USER-ID abgefragt, nicht
// über die Mitgliedschafts-ID.
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

// CreateOrganization legt eine Organisation an, deren Owner das API-Konto wird. Bitwarden ist
// Ende-zu-Ende-verschlüsselt, deshalb erzeugt dieser Client Organisations-Schlüssel und Schlüsselpaar
// selbst. Dafür braucht er wie Confirm das Master-Passwort. Namen sind auf dem Server nicht eindeutig,
// Aufrufer müssen selbst auf Duplikate prüfen.
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
		"planType":       0, // ignoriert Vaultwarden, das Feld ist aber Pflicht
	}, &created)
	if err != nil {
		return model.Organization{}, err
	}
	if created.ID == "" {
		return model.Organization{}, errors.New("server returned no organization id")
	}
	return model.Organization{ID: created.ID, Name: created.Name, EncryptedKey: keys.Key}, nil
}

// api ruft /api{path} auf. Ein 401 löst einen neuen Login und einen zweiten Versuch aus, weil das Token
// abgelaufen sein kann.
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

// bearer liefert ein gültiges Access-Token. Es meldet sich an, wenn keins existiert, das vorhandene
// bald abläuft oder force gesetzt ist.
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
		// Pro API-Key konstant, damit der Server nicht bei jedem Login ein neues Gerät registriert.
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
		return r[strings.ToLower(name[:1])+name[1:]] // manche Serverversionen schreiben "key", andere "Key"
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

// do führt einen HTTP-Request aus. Statuscodes ab 400 und Netzwerkfehler werden zu *APIError.
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
		// url.Error wiederholt nur die URL, keinen Body, und darf deshalb angezeigt werden.
		return &APIError{Method: method, Path: path, Body: err.Error()}
	}
	defer func() { _ = resp.Body.Close() }()
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

// deviceID leitet aus der Client-ID eine stabile Geräte-ID in UUID-Form ab. Sie ist nur ein Bezeichner
// und kein Secret. SHA-256 statt eines schwächeren Hashs hält Sicherheits-Scanner ruhig.
func deviceID(clientID string) string {
	sum := sha256.Sum256([]byte("vwsync/" + clientID))
	h := hex.EncodeToString(sum[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

// truncate kürzt s auf höchstens n Byte, ohne ein Mehrbyte-Zeichen zu zerschneiden.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// HTTPClient liefert den HTTP-Client für Vaultwarden. caFile ist eine optionale PEM-Datei, deren
// Zertifizierungsstellen zusätzlich zu denen des Systems vertraut wird, für einen Server mit interner CA.
func HTTPClient(caFile string, timeout time.Duration) (*http.Client, error) {
	client := &http.Client{Timeout: timeout}
	if caFile == "" {
		return client, nil
	}
	pemData, err := os.ReadFile(caFile) //nolint:gosec // der Pfad stammt aus der Konfiguration des Betreibers
	if err != nil {
		return nil, fmt.Errorf("reading VW_CA_FILE: %w", err)
	}
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}
	if !pool.AppendCertsFromPEM(pemData) {
		return nil, fmt.Errorf("VW_CA_FILE %s contains no PEM certificate", caFile)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	client.Transport = transport
	return client, nil
}
