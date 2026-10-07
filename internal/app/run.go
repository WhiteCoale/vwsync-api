// Package app steuert den Lebenszyklus des Dienstes: Start, Bereitschaft, Neuladen und geordnetes
// Herunterfahren. main liest nur die Konfiguration und reicht die Signale des Betriebssystems durch,
// damit sich der ganze Ablauf ohne echte Signale und ohne systemd testen lässt.
//
// Ablauf unter systemd (Type=notify):
//
//	start    Konfiguration prüfen, Log öffnen, Port belegen, bei Vaultwarden anmelden, READY=1 senden
//	reload   SIGHUP: Logdatei neu öffnen (nach logrotate), danach wieder READY=1
//	stop     SIGTERM: STOPPING=1, keine neuen Verbindungen, laufende Requests zu Ende führen
//	         ein zweites SIGTERM bricht laufende Requests ab
//	watchdog solange der Dienst auf /healthz antwortet, regelmäßig WATCHDOG=1
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"syscall"
	"time"

	"vwsync-api/internal/config"
	"vwsync-api/internal/daemon"
	"vwsync-api/internal/logfile"
	"vwsync-api/internal/reconcile"
	"vwsync-api/internal/server"
	"vwsync-api/internal/vaultwarden"
)

// ExitConfig ist der Exit-Code für Fehler in der Konfiguration (EX_CONFIG aus sysexits.h). Die
// systemd-Unit startet den Dienst bei diesem Code nicht neu, denn ein Neustart ändert daran nichts.
const ExitConfig = 78

// ExitError trägt den Exit-Code, mit dem main den Prozess beenden soll.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func configError(format string, args ...any) error {
	return &ExitError{Code: ExitConfig, Err: fmt.Errorf(format, args...)}
}

const (
	// shutdownGrace ist die Zeit, die laufende Requests beim Herunterfahren bekommen. Sie liegt knapp
	// unter TimeoutStopSec=900 der Unit, damit der Dienst sich selbst beendet, bevor systemd ihn tötet.
	shutdownGrace = 14 * time.Minute
	// startupLoginTimeout begrenzt den Login beim Start.
	startupLoginTimeout = 30 * time.Second
	// defaultRetryInterval ist der Abstand der Login-Versuche, solange Vaultwarden seit dem Start nicht
	// erreichbar war.
	defaultRetryInterval = 30 * time.Second
)

// Options ist alles, was Run von außen braucht.
type Options struct {
	Config  config.Config
	Version string
	// Signals liefert SIGTERM, SIGINT und SIGHUP.
	Signals <-chan os.Signal
	// Notifier meldet den Zustand an systemd.
	Notifier daemon.Notifier
	// Watchdog ist das Intervall für WATCHDOG=1, 0 schaltet den Watchdog ab.
	Watchdog time.Duration
	// Stderr nimmt das Log auf, wenn keine Logdatei konfiguriert ist.
	Stderr io.Writer
	// Listener ist optional. Ohne ihn belegt Run die Adresse aus der Konfiguration.
	Listener net.Listener
	// RetryInterval ist der Abstand der Login-Versuche nach einem gestörten Start, 0 bedeutet 30 Sekunden.
	RetryInterval time.Duration
}

// Run startet den Dienst und kehrt zurück, wenn er beendet ist. nil bedeutet ein geordnetes Ende.
func Run(o Options) error {
	cfg := o.Config

	// Log: Datei oder Standardfehlerausgabe. Ein Fehler hier ist ein Konfigurationsfehler, etwa ein
	// fehlendes Verzeichnis oder fehlende Rechte.
	out := o.Stderr
	var lf *logfile.File
	if cfg.LogFile != "" {
		var err error
		if lf, err = logfile.Open(cfg.LogFile); err != nil {
			return configError("VWSYNC_LOG_FILE: %w", err)
		}
		defer func() { _ = lf.Close() }()
		out = lf
	}
	log := newLogger(out, cfg)

	httpClient, err := vaultwarden.HTTPClient(cfg.VWCAFile, 30*time.Second)
	if err != nil {
		return configError("%w", err)
	}
	vw := vaultwarden.New(httpClient, cfg.VWURL, vaultwarden.Credentials{
		ClientID:       cfg.VWClientID,
		ClientSecret:   cfg.VWClientSecret,
		MasterPassword: cfg.VWMasterPassword,
	}).WithLogger(log)

	ln := o.Listener
	if ln == nil {
		if ln, err = net.Listen("tcp", cfg.Listen); err != nil {
			// Etwa ein belegter Port. Das kann vorübergehend sein, systemd darf neu starten.
			return fmt.Errorf("listening on %s: %w", cfg.Listen, err)
		}
	}
	defer func() { _ = ln.Close() }()

	// Ein abgelehnter API-Key verhindert den Start, ein Neustart würde nichts ändern. Ist Vaultwarden
	// dagegen nur nicht erreichbar, etwa weil der andere Server neu startet, läuft der Dienst trotzdem an.
	// Er meldet sich dann beim ersten Request an, und /readyz zeigt den Zustand.
	status := "ready"
	reachable := true
	loginCtx, cancel := context.WithTimeout(context.Background(), startupLoginTimeout)
	_, err = vw.Login(loginCtx)
	cancel()
	switch {
	case vaultwarden.CredentialsRejected(err):
		log.Error("vaultwarden rejected the API key", "err", err)
		return configError("vaultwarden rejected the API key: %w", err)
	case err != nil:
		log.Warn("vaultwarden is not reachable, starting anyway; the service logs in on the first request", "err", err)
		status = "ready, vaultwarden not reachable at startup"
		reachable = false
	}

	// statusText ist die Statuszeile für systemd. reload meldet sie erneut, retryLogin aktualisiert sie.
	var statusText atomic.Value
	statusText.Store(status)

	var stopping atomic.Bool
	srv := &http.Server{
		Handler: server.New(server.Deps{
			Auth: cfg.APIKeys, Dir: vaultDir{vw}, Log: log, TrustProxy: cfg.TrustProxy,
			Ping: vw.Ping, Stopping: &stopping,
		}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute, // ein Sync oder Confirm kann mehrere Minuten dauern
		IdleTimeout:       60 * time.Second,
		ErrorLog:          slog.NewLogLogger(log.Handler(), slog.LevelWarn),
	}
	serveErr := make(chan error, 1)
	go func() { serveErr <- srv.Serve(ln) }()

	notify(o.Notifier, log, "READY=1\nSTATUS="+status)
	log.Info("listening", "addr", ln.Addr().String(), "version", o.Version,
		"confirm_enabled", cfg.VWMasterPassword != "", "log_file", cfg.LogFile)

	background := make(chan struct{})
	defer close(background)
	if o.Watchdog > 0 {
		go watchdog(o.Watchdog, "http://"+ln.Addr().String()+"/healthz", &stopping, o.Notifier, log, background)
	}
	if !reachable {
		interval := o.RetryInterval
		if interval <= 0 {
			interval = defaultRetryInterval
		}
		go retryLogin(vw, interval, &statusText, o.Notifier, log, background)
	}

	// Betrieb: auf Signale warten.
	for {
		select {
		case err := <-serveErr:
			// Der Server endet nur so, wenn etwas schiefgeht, denn Shutdown wurde noch nicht aufgerufen.
			log.Error("http server stopped unexpectedly", "err", err)
			return err
		case sig := <-o.Signals:
			if sig == syscall.SIGHUP {
				reload(o.Notifier, log, lf, &statusText)
				continue
			}
			log.Info("stopping", "signal", sig.String())
			return shutdown(srv, &stopping, o, log, lf, &statusText)
		}
	}
}

// retryLogin versucht nach einem gestörten Start regelmäßig, sich bei Vaultwarden anzumelden. Klappt
// es, setzt es die Statuszeile von systemd wieder auf "ready" und endet. Requests warten nicht darauf,
// sie melden sich bei Bedarf selbst an. Ein abgelehnter API-Key wird nur protokolliert, denn der Dienst
// läuft bereits.
func retryLogin(vw *vaultwarden.Client, interval time.Duration, statusText *atomic.Value, n daemon.Notifier, log *slog.Logger, done <-chan struct{}) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		ctx, cancel := context.WithTimeout(context.Background(), startupLoginTimeout)
		_, err := vw.Login(ctx)
		cancel()
		switch {
		case err == nil:
			log.Info("vaultwarden is reachable again")
			statusText.Store("ready")
			notify(n, log, "STATUS=ready")
			return
		case vaultwarden.CredentialsRejected(err):
			log.Error("vaultwarden rejected the API key", "err", err)
		default:
			log.Warn("vaultwarden is still not reachable", "err", err)
		}
	}
}

// shutdown fährt den Server geordnet herunter. Neue Verbindungen werden abgewiesen, laufende Requests
// dürfen bis zu shutdownGrace zu Ende laufen. Ein schreibender Lauf hinterlässt so keinen halben
// Zustand. Ein zweites Stopp-Signal bricht sofort ab.
func shutdown(srv *http.Server, stopping *atomic.Bool, o Options, log *slog.Logger, lf *logfile.File, statusText *atomic.Value) error {
	stopping.Store(true)
	notify(o.Notifier, log, "STOPPING=1\nSTATUS=stopping, waiting for running requests")

	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- srv.Shutdown(ctx) }()

	for {
		select {
		case err := <-done:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Warn("running requests did not finish in time", "err", err)
				_ = srv.Close()
			}
			log.Info("stopped")
			return nil
		case sig := <-o.Signals:
			if sig == syscall.SIGHUP {
				reload(o.Notifier, log, lf, statusText)
				continue
			}
			log.Warn("second stop signal, aborting running requests", "signal", sig.String())
			_ = srv.Close()
		}
	}
}

// reload öffnet die Logdatei neu, etwa nachdem logrotate sie umbenannt hat.
func reload(n daemon.Notifier, log *slog.Logger, lf *logfile.File, statusText *atomic.Value) {
	notify(n, log, "RELOADING=1\nSTATUS=reloading")
	if lf != nil {
		if err := lf.Reopen(); err != nil {
			log.Error("could not reopen the log file, still writing to the old one", "err", err)
		} else {
			log.Info("log file reopened", "path", lf.Path())
		}
	}
	notify(n, log, "READY=1\nSTATUS="+statusText.Load().(string))
}

// watchdog meldet WATCHDOG=1, solange der Dienst auf /healthz antwortet. Hängt der HTTP-Server, bleibt
// die Meldung aus, und systemd startet den Dienst neu. Während des Herunterfahrens ist der Port schon
// geschlossen. Dann meldet der Watchdog ohne Prüfung weiter, damit systemd einen laufenden Sync nicht
// abbricht.
func watchdog(interval time.Duration, url string, stopping *atomic.Bool, n daemon.Notifier, log *slog.Logger, done <-chan struct{}) {
	client := &http.Client{Timeout: interval / 2}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
		}
		if stopping.Load() || healthy(client, url) {
			notify(n, log, "WATCHDOG=1")
		} else {
			log.Warn("watchdog: /healthz did not answer, not reporting alive")
		}
	}
}

func healthy(client *http.Client, url string) bool {
	resp, err := client.Get(url) //nolint:noctx // der Timeout des Clients begrenzt den Aufruf
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

func notify(n daemon.Notifier, log *slog.Logger, state string) {
	if n == nil {
		return
	}
	if err := n.Notify(state); err != nil {
		log.Warn("could not notify systemd", "err", err)
	}
}

func newLogger(w io.Writer, cfg config.Config) *slog.Logger {
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	if cfg.LogJSON {
		return slog.New(slog.NewJSONHandler(w, opts))
	}
	return slog.New(slog.NewTextHandler(w, opts))
}

// vaultDir passt den Vaultwarden-Client an server.Directory an. Der einzige Unterschied ist der
// Rückgabetyp von Vault. Der Server erwartet das kleine Interface reconcile.OrgKeys, der Client
// liefert *crypto.KeyVault.
type vaultDir struct{ *vaultwarden.Client }

func (d vaultDir) Vault(ctx context.Context) (reconcile.OrgKeys, error) {
	v, err := d.Client.Vault(ctx)
	if err != nil {
		return nil, err
	}
	return v, nil
}
