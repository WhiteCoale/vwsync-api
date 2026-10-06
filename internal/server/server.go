// Package server is the HTTP layer: routing, authentication, request validation, error mapping.
// All business logic lives in package reconcile.
package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"vwsync-api/internal/auth"
	"vwsync-api/internal/model"
	"vwsync-api/internal/reconcile"
	"vwsync-api/internal/vaultwarden"
)

const (
	maxBodyBytes        = 1 << 20
	defaultMaxRemovals  = 5
	writeTimeout        = 10 * time.Minute
	loginFailuresPerMin = 5
	maxOrgNameLen       = 50
)

// Directory is everything the handlers need from Vaultwarden: the reconcile operations plus the
// key vault for confirm. *vaultwarden.Client implements it.
type Directory interface {
	reconcile.Directory
	Vault(ctx context.Context) (reconcile.OrgKeys, error)
}

// Deps are the collaborators of the server.
type Deps struct {
	Auth       *auth.Authenticator
	Dir        Directory
	Log        *slog.Logger
	TrustProxy bool
}

type server struct {
	Deps
	svc     *reconcile.Service
	limiter *auth.Limiter
	// writeMu serializes sync and confirm. Two concurrent writers would plan against the same
	// state and invite or remove twice. Requests do not queue: a second one gets 409.
	writeMu sync.Mutex
}

// New builds the HTTP handler.
func New(d Deps) http.Handler {
	s := &server{Deps: d, svc: reconcile.NewService(d.Dir), limiter: auth.NewLimiter(loginFailuresPerMin, time.Minute)}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.HandleFunc("POST /v1/auth/login", s.login)
	mux.Handle("GET /v1/orgs", s.authed(s.listOrgs))
	mux.Handle("POST /v1/orgs", s.authed(s.createOrg))
	mux.Handle("GET /v1/orgs/{org}/members", s.authed(s.orgMembers))
	mux.Handle("GET /v1/export", s.authed(s.export))
	mux.Handle("POST /v1/sync", s.authed(s.sync))
	mux.Handle("POST /v1/confirm", s.authed(s.confirm))

	return s.logging(s.recoverPanic(mux))
}

// --- auth ---------------------------------------------------------------------------------------

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	ip := s.clientIP(r)
	if blocked, wait := s.limiter.Blocked(ip); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		writeError(w, http.StatusTooManyRequests, "too many failed logins, try again later")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	token, expires, ok := s.Auth.Login(req.Username, req.Password)
	if !ok {
		s.limiter.Fail(ip)
		s.Log.Warn("login failed", "ip", ip)
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.limiter.Reset(ip)
	writeJSON(w, 200, map[string]any{
		"access_token": token,
		"token_type":   "Bearer",
		"expires_in":   int(time.Until(expires).Seconds()),
	})
}

func (s *server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || s.Auth.Verify(token) != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vwsync-api"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid token")
			return
		}
		next(w, r)
	})
}

// clientIP is the key used for rate limiting. Behind nginx every request comes from the proxy, so with
// TrustProxy the real address is read from X-Real-IP. The header is believed only when the request
// itself comes from the loopback interface, where nginx runs. Otherwise anyone who can reach the
// port could invent an address and dodge the limit.
//
// IPv6 clients are grouped by their /64 prefix: one subscriber usually owns a whole /64, and
// rotating inside it would otherwise give an attacker unlimited fresh addresses.
func (s *server) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	addr := remote
	if s.TrustProxy && isLoopback(remote) {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
			addr = ip
		}
	}
	return limiterKey(addr)
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// limiterKey normalizes an address: IPv4 as is, IPv6 reduced to its /64 prefix. Anything that is not
// an IP address is used unchanged.
func limiterKey(addr string) string {
	ip := net.ParseIP(addr)
	if ip == nil {
		return addr
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.Mask(net.CIDRMask(64, 128)).String() + "/64"
}

// --- read endpoints -----------------------------------------------------------------------------

func (s *server) listOrgs(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.Dir.AdminOrganizations(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"orgs": orgs})
}

// createOrg creates an organization owned by the API account. Dry run is the default.
func (s *server) createOrg(w http.ResponseWriter, r *http.Request) {
	apply, ok := queryBool(w, r.URL.Query().Get("apply"), "apply")
	if !ok {
		return
	}
	var body struct {
		Name         string `json:"name"`
		BillingEmail string `json:"billing_email"`
	}
	if !decodeJSON(w, r, &body) {
		return
	}
	body.Name = strings.TrimSpace(body.Name)
	if n := utf8.RuneCountInString(body.Name); n < 1 || n > maxOrgNameLen {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf("name must be 1 to %d characters", maxOrgNameLen))
		return
	}
	if body.BillingEmail != "" {
		if a, err := mail.ParseAddress(body.BillingEmail); err != nil || a.Address != body.BillingEmail {
			writeError(w, http.StatusUnprocessableEntity, "billing_email is not a valid e-mail address")
			return
		}
	}

	ctx := r.Context()
	if apply {
		if !s.writeMu.TryLock() {
			writeError(w, http.StatusConflict, "another write operation is running")
			return
		}
		defer s.writeMu.Unlock()
		// Creating must not be cut off half way: the server would keep an org the caller never heard of.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
	}
	org, err := s.svc.CreateOrg(ctx, body.Name, body.BillingEmail, apply)
	if err != nil {
		s.fail(w, err)
		return
	}
	if !apply {
		writeJSON(w, http.StatusOK, map[string]any{"dry_run": true, "org": map[string]string{"name": org.Name}})
		return
	}
	s.Log.Info("organization created", "org", org.Name, "id", org.ID)
	writeJSON(w, http.StatusCreated, map[string]any{"dry_run": false, "org": org})
}

type orgMembers struct {
	model.Organization
	Members []model.Member `json:"members"`
}

func (s *server) orgMembers(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.Dir.AdminOrganizations(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	o, err := reconcile.FindOrg(orgs, r.PathValue("org"))
	if err != nil {
		s.fail(w, err)
		return
	}
	members, err := s.Dir.OrgUsers(r.Context(), o.ID)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, 200, orgMembers{o, members})
}

// export returns the actual state of every admin org. "desired" has the shape of a sync request
// body (revoked members left out), so the response can be edited and sent back to /v1/sync.
func (s *server) export(w http.ResponseWriter, r *http.Request) {
	orgs, err := s.Dir.AdminOrganizations(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	type desiredOrg struct {
		Members map[string]model.Role `json:"members"`
	}
	out := make([]orgMembers, 0, len(orgs))
	desired := map[string]desiredOrg{}
	for _, o := range orgs {
		members, err := s.Dir.OrgUsers(r.Context(), o.ID)
		if err != nil {
			s.fail(w, err)
			return
		}
		out = append(out, orgMembers{o, members})
		d := desiredOrg{Members: map[string]model.Role{}}
		for _, m := range members {
			// Revoked members stay out, otherwise a sync would "expect" them.
			if m.Status != model.Revoked {
				d.Members[m.Email] = m.Role
			}
		}
		desired[o.Name] = d
	}
	writeJSON(w, 200, map[string]any{"orgs": out, "desired": map[string]any{"orgs": desired}})
}

// --- write endpoints ----------------------------------------------------------------------------

type orgSync struct {
	reconcile.OrgPlan
	Results []reconcile.ChangeResult `json:"results,omitempty"`
}

// sync plans, and with apply=true executes, the desired state. Dry run is the default.
func (s *server) sync(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	apply, ok1 := queryBool(w, q.Get("apply"), "apply")
	noRemove, ok2 := queryBool(w, q.Get("no_remove"), "no_remove")
	limit, ok3 := queryInt(w, q.Get("max_removals"), "max_removals", defaultMaxRemovals)
	if !ok1 || !ok2 || !ok3 {
		return
	}
	var input reconcile.DesiredInput
	if !decodeJSON(w, r, &input) {
		return
	}
	desired, err := input.Parse()
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, err.Error())
		return
	}

	ctx := r.Context()
	if apply {
		if !s.writeMu.TryLock() {
			writeError(w, http.StatusConflict, "another write operation is running")
			return
		}
		defer s.writeMu.Unlock()
		// A caller that hangs up must not leave a half-applied run behind.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
	}

	plans, err := s.svc.Plan(ctx, desired, !noRemove)
	if err != nil {
		s.fail(w, err)
		return
	}

	// Removal limit across ALL orgs, checked before anything changes. It protects against an
	// accidentally empty or wrong request that would remove every member.
	removals := 0
	for _, p := range plans {
		removals += p.Removals()
	}
	if removals > limit {
		writeError(w, http.StatusUnprocessableEntity, fmt.Sprintf(
			"%d removals planned, the limit is %d. Check the request or raise max_removals.", removals, limit))
		return
	}

	failures := 0
	out := make([]orgSync, 0, len(plans))
	for _, p := range plans {
		o := orgSync{OrgPlan: p}
		if apply {
			o.Results = s.svc.Apply(ctx, p)
			for _, res := range o.Results {
				if !res.OK {
					failures++
				}
			}
			s.auditSync(p.Org.Name, o.Results)
		}
		out = append(out, o)
	}

	status := http.StatusOK
	if failures > 0 {
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, map[string]any{"dry_run": !apply, "failures": failures, "plans": out})
}

// confirm confirms members whose status is "accepted". Dry run is the default.
//
// Confirming trusts the public key the server hands out for the member, so the caller must either
// name the e-mail addresses to confirm or pass all=true explicitly.
func (s *server) confirm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	apply, ok1 := queryBool(w, q.Get("apply"), "apply")
	all, ok2 := queryBool(w, q.Get("all"), "all")
	if !ok1 || !ok2 {
		return
	}
	var body struct {
		Emails []string `json:"emails"`
	}
	if !decodeOptionalJSON(w, r, &body) {
		return
	}
	var only map[string]bool
	switch {
	case len(body.Emails) > 0 && all:
		writeError(w, http.StatusBadRequest, "pass either emails or all=true, not both")
		return
	case len(body.Emails) > 0:
		only = map[string]bool{}
		for _, e := range body.Emails {
			only[strings.ToLower(strings.TrimSpace(e))] = true
		}
	case !all:
		writeError(w, http.StatusBadRequest, `send {"emails": [...]} to confirm specific members, or pass all=true`)
		return
	}

	ctx := r.Context()
	if apply {
		if !s.writeMu.TryLock() {
			writeError(w, http.StatusConflict, "another write operation is running")
			return
		}
		defer s.writeMu.Unlock()
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
	}

	orgs, err := s.svc.ConfirmAll(ctx, only, apply, func(ctx context.Context) (reconcile.OrgKeys, error) { return s.Dir.Vault(ctx) })
	if err != nil {
		s.fail(w, err)
		return
	}
	failures := 0
	for _, o := range orgs {
		for _, res := range o.Results {
			if !res.OK {
				failures++
			}
		}
		if apply {
			s.auditConfirm(o.Org.Name, o.Results)
		}
	}
	status := http.StatusOK
	if failures > 0 {
		status = http.StatusMultiStatus
	}
	writeJSON(w, status, map[string]any{"dry_run": !apply, "failures": failures, "orgs": orgs})
}

// auditSync writes one log line per executed change, so the log says who was invited, changed or removed.
func (s *server) auditSync(org string, results []reconcile.ChangeResult) {
	for _, r := range results {
		attrs := []any{"org", org, "type", string(r.Type), "email", r.Email, "ok", r.OK}
		if r.Role != nil {
			attrs = append(attrs, "role", r.Role.String())
		}
		if r.From != nil {
			attrs = append(attrs, "from", r.From.String())
		}
		if r.OK {
			s.Log.Info("audit", attrs...)
		} else {
			s.Log.Warn("audit", append(attrs, "error", r.Error)...)
		}
	}
}

func (s *server) auditConfirm(org string, results []reconcile.ConfirmResult) {
	for _, r := range results {
		attrs := []any{"org", org, "type", "confirm", "email", r.Email, "ok", r.OK}
		if r.OK {
			s.Log.Info("audit", attrs...)
		} else {
			s.Log.Warn("audit", append(attrs, "error", r.Error)...)
		}
	}
}

// --- helpers ------------------------------------------------------------------------------------

// fail maps an internal error to an HTTP status. Messages never contain secrets or request bodies.
func (s *server) fail(w http.ResponseWriter, err error) {
	var notFound *reconcile.OrgNotFoundError
	var exists *reconcile.OrgExistsError
	var ambiguous *reconcile.OrgAmbiguousError
	var apiErr *vaultwarden.APIError
	switch {
	case errors.As(err, &notFound):
		writeError(w, http.StatusNotFound, err.Error())
	case errors.As(err, &ambiguous):
		writeError(w, http.StatusUnprocessableEntity, err.Error())
	case errors.As(err, &exists):
		writeError(w, http.StatusConflict, err.Error())
	case errors.Is(err, vaultwarden.ErrNoMasterPassword):
		writeError(w, http.StatusServiceUnavailable, err.Error())
	case errors.As(err, &apiErr):
		s.Log.Error("vaultwarden call failed", "err", err)
		writeError(w, http.StatusBadGateway, err.Error())
	default:
		s.Log.Error("request failed", "err", err)
		writeError(w, http.StatusInternalServerError, err.Error())
	}
}

func decodeJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return readJSON(w, r, v, false)
}

// decodeOptionalJSON is decodeJSON for endpoints where the body may be left out entirely. An empty
// body counts as absent whether it comes with Content-Length: 0 or as an empty chunked stream.
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return readJSON(w, r, v, true)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields() // a typo like "membres" must not silently mean "remove everyone"
	if err := dec.Decode(v); err != nil {
		if optional && errors.Is(err, io.EOF) {
			return true
		}
		writeError(w, http.StatusBadRequest, "invalid JSON body: "+err.Error())
		return false
	}
	if dec.More() {
		writeError(w, http.StatusBadRequest, "invalid JSON body: trailing data")
		return false
	}
	return true
}

func queryBool(w http.ResponseWriter, raw, name string) (bool, bool) {
	if raw == "" {
		return false, true
	}
	b, err := strconv.ParseBool(raw)
	if err != nil {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("query parameter %s must be true or false", name))
		return false, false
	}
	return b, true
}

func queryInt(w http.ResponseWriter, raw, name string, def int) (int, bool) {
	if raw == "" {
		return def, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("query parameter %s must be a non-negative integer", name))
		return 0, false
	}
	return n, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	w.status = code
	w.ResponseWriter.WriteHeader(code)
}

// logging records method, path, query, status and duration. Never headers or bodies: they hold tokens and passwords.
func (s *server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		// The query only holds flags such as apply=true. It is what tells a dry run from a write.
		s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "query", r.URL.RawQuery, "status", sw.status, "ms", time.Since(start).Milliseconds())
	})
}

func (s *server) recoverPanic(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				id := make([]byte, 4)
				_, _ = rand.Read(id)
				ref := hex.EncodeToString(id)
				s.Log.Error("panic", "ref", ref, "value", fmt.Sprint(rec), "stack", string(debug.Stack()))
				writeError(w, http.StatusInternalServerError, "internal error (ref "+ref+")")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
