// Package server ist die HTTP-Schicht mit Routing, Authentifizierung, Prüfung der Requests und
// Abbildung von Fehlern auf Statuscodes. Die Fachlogik liegt im Paket reconcile.
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
	"net/url"
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
	maxBodyBytes       = 1 << 20
	defaultMaxRemovals = 5
	writeTimeout       = 10 * time.Minute
	maxOrgNameLen      = 50
)

// Directory ist alles, was die Handler von Vaultwarden brauchen, also die Operationen für den Abgleich
// und den Schlüsseltresor für confirm. *vaultwarden.Client implementiert es.
type Directory interface {
	reconcile.Directory
	Vault(ctx context.Context) (reconcile.OrgKeys, error)
}

// Deps sind die Abhängigkeiten des Servers.
type Deps struct {
	Auth       *auth.Keys
	Dir        Directory
	Log        *slog.Logger
	TrustProxy bool
}

type server struct {
	Deps
	svc *reconcile.Service
	// writeMu serialisiert die schreibenden Aufrufe. Zwei gleichzeitige Schreiber würden gegen denselben
	// Zustand planen und doppelt einladen oder entfernen. Requests warten nicht, ein zweiter erhält 409.
	writeMu sync.Mutex
}

// New baut den HTTP-Handler.
func New(d Deps) http.Handler {
	s := &server{Deps: d, svc: reconcile.NewService(d.Dir)}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, 200, map[string]string{"status": "ok"}) })
	mux.Handle("GET /v1/orgs", s.authed(s.listOrgs))
	mux.Handle("POST /v1/orgs", s.authed(s.createOrg))
	mux.Handle("GET /v1/orgs/{org}/members", s.authed(s.orgMembers))
	mux.Handle("GET /v1/export", s.authed(s.export))
	mux.Handle("POST /v1/sync", s.authed(s.sync))
	mux.Handle("POST /v1/confirm", s.authed(s.confirm))

	return s.logging(s.recoverPanic(mux))
}

// --- auth ---------------------------------------------------------------------------------------

// authed lässt einen Request nur durch, wenn er einen gültigen Zugangsschlüssel als
// "Authorization: Bearer <Schlüssel>" trägt. Ein abgewiesener Request wird mit der Adresse des
// Aufrufers protokolliert, aber nie mit dem vorgelegten Schlüssel.
func (s *server) authed(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		scheme, key, found := strings.Cut(r.Header.Get("Authorization"), " ")
		if !found || !strings.EqualFold(scheme, "Bearer") || !s.Auth.Verify(strings.TrimSpace(key)) {
			s.Log.Warn("request rejected", "reason", "missing or invalid API key", "ip", s.clientIP(r), "method", r.Method, "path", r.URL.Path)
			w.Header().Set("WWW-Authenticate", `Bearer realm="vwsync-api"`)
			writeError(w, http.StatusUnauthorized, "missing or invalid API key")
			return
		}
		next(w, r)
	})
}

// clientIP ist die Adresse des Aufrufers für das Log. Hinter nginx kommt jeder Request vom Proxy, mit
// TrustProxy wird die echte Adresse deshalb aus X-Real-IP gelesen. Der Header gilt nur, wenn der
// Request selbst von der Loopback-Schnittstelle kommt, wo nginx läuft. Sonst könnte jeder, der den
// Port erreicht, eine beliebige Adresse ins Log schreiben.
func (s *server) clientIP(r *http.Request) string {
	remote := r.RemoteAddr
	if host, _, err := net.SplitHostPort(remote); err == nil {
		remote = host
	}
	if s.TrustProxy && isLoopback(remote) {
		if ip := strings.TrimSpace(r.Header.Get("X-Real-IP")); ip != "" {
			return ip
		}
	}
	return remote
}

func isLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

// createOrg legt eine Organisation an, deren Owner das API-Konto wird. dry_run=true prüft nur den Namen.
func (s *server) createOrg(w http.ResponseWriter, r *http.Request) {
	apply, ok := writeMode(w, r.URL.Query())
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
		// Das Anlegen darf nicht mittendrin abbrechen, sonst bliebe eine Org zurück, von der der Aufrufer
		// nichts weiß.
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

// export liefert den Ist-Zustand jeder verwalteten Org. "desired" hat die Form eines Sync-Bodys (ohne
// gesperrte Mitglieder), die Antwort lässt sich also bearbeiten und an /v1/sync zurückschicken.
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
			// Gesperrte Mitglieder bleiben draußen, sonst würde ein Sync sie "erwarten".
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

// sync plant den Soll-Zustand und führt den Plan aus. Mit dry_run=true liefert er nur den Plan.
func (s *server) sync(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	apply, ok := writeMode(w, q)
	if !ok {
		return
	}
	noRemove, ok := queryBool(w, q.Get("no_remove"), "no_remove")
	if !ok {
		return
	}
	limit, ok := queryInt(w, q.Get("max_removals"), "max_removals", defaultMaxRemovals)
	if !ok {
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
		// Ein Aufrufer, der die Verbindung trennt, darf keinen halb ausgeführten Lauf hinterlassen.
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.WithoutCancel(ctx), writeTimeout)
		defer cancel()
	}

	plans, err := s.svc.Plan(ctx, desired, !noRemove)
	if err != nil {
		s.fail(w, err)
		return
	}

	// Obergrenze für Entfernungen über ALLE Orgs, geprüft vor jeder Änderung. Sie schützt vor einem
	// versehentlich leeren oder falschen Request, der alle Mitglieder entfernen würde.
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

// confirm bestätigt Mitglieder mit Status "accepted". Mit dry_run=true listet er sie nur auf.
//
// Beim Bestätigen wird dem öffentlichen Schlüssel vertraut, den der Server für das Mitglied liefert.
// Deshalb muss der Aufrufer entweder die zu bestätigenden Adressen nennen oder ausdrücklich all=true
// setzen.
func (s *server) confirm(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	apply, ok := writeMode(w, q)
	if !ok {
		return
	}
	all, ok := queryBool(w, q.Get("all"), "all")
	if !ok {
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

// auditSync schreibt je ausgeführter Änderung eine Logzeile, damit das Log zeigt, wer eingeladen,
// geändert oder entfernt wurde.
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

// loggedParams sind die Query-Parameter, die der Dienst kennt. Es sind Schalter und Zahlen, nichts
// Geheimes.
var loggedParams = []string{"dry_run", "no_remove", "max_removals", "all"}

// loggableQuery liefert die bekannten Parameter für das Access-Log. Alles andere bleibt draußen, weil
// ein Aufrufer, der den Zugangsschlüssel fälschlich als ?key=... sendet, ihn sonst ins Log schreiben
// würde.
func loggableQuery(q url.Values) string {
	out := url.Values{}
	for _, name := range loggedParams {
		if v, ok := q[name]; ok {
			out[name] = v
		}
	}
	return out.Encode()
}

// --- helpers ------------------------------------------------------------------------------------

// fail bildet einen internen Fehler auf einen HTTP-Status ab. Meldungen enthalten nie Secrets oder
// Request-Bodies.
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

// decodeOptionalJSON ist decodeJSON für Endpunkte, bei denen der Body ganz fehlen darf. Ein leerer
// Body gilt als nicht vorhanden, egal ob er mit Content-Length: 0 oder als leerer Chunked-Stream kommt.
func decodeOptionalJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	return readJSON(w, r, v, true)
}

func readJSON(w http.ResponseWriter, r *http.Request, v any, optional bool) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	dec.DisallowUnknownFields() // ein Tippfehler wie "membres" darf nicht still "alle entfernen" bedeuten
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

// writeMode liest, wie ein schreibender Endpunkt läuft. Standard ist Ausführen, dry_run=true liefert
// nur eine Vorschau.
//
// Der Parameter apply wird bewusst abgelehnt statt ignoriert. Ein Aufrufer, der apply=false sendet und
// eine Vorschau erwartet, würde sonst still ausführen.
func writeMode(w http.ResponseWriter, q url.Values) (apply, ok bool) {
	if _, legacy := q["apply"]; legacy {
		writeError(w, http.StatusBadRequest, "the apply parameter does not exist: writes run directly, pass dry_run=true to preview")
		return false, false
	}
	dryRun, ok := queryBool(w, q.Get("dry_run"), "dry_run")
	return !dryRun, ok
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

// logging protokolliert Methode, Pfad, bekannte Query-Parameter, Status und Dauer. Nie Header oder
// Bodies, denn die enthalten Schlüssel und Passwörter.
func (s *server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		s.Log.Info("request", "method", r.Method, "path", r.URL.Path, "query", loggableQuery(r.URL.Query()), "status", sw.status, "ms", time.Since(start).Milliseconds())
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
