// Command vwsync-api ist ein REST-Dienst, der Organisationen und Mitglieder in Vaultwarden abgleicht.
//
//	vwsync-api                startet den Dienst (wie "serve")
//	vwsync-api generate-key   erzeugt einen Zugangsschlüssel für Aufrufer und den Hash für die Konfiguration
//	vwsync-api version        gibt die Version aus, aus der dieses Binary gebaut wurde
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"
	"time"

	"vwsync-api/internal/auth"
	"vwsync-api/internal/config"
	"vwsync-api/internal/reconcile"
	"vwsync-api/internal/server"
	"vwsync-api/internal/vaultwarden"
)

// version wird beim Bauen mit -ldflags "-X main.version=v1.2.3" gesetzt. Ohne diese Angabe nennt das
// Binary trotzdem den Commit, aus dem es gebaut wurde. Go bettet ihn in die Build-Informationen ein.
var version = "dev"

// buildInfo liefert die Version und, wenn das Binary in einem Git-Checkout gebaut wurde, den Commit.
func buildInfo() string {
	out := version
	if info, ok := debug.ReadBuildInfo(); ok {
		var rev, modified string
		for _, kv := range info.Settings {
			switch kv.Key {
			case "vcs.revision":
				rev = kv.Value
			case "vcs.modified":
				modified = kv.Value
			}
		}
		if len(rev) > 12 {
			rev = rev[:12]
		}
		if rev != "" {
			out += " (" + rev
			if modified == "true" {
				out += ", modified"
			}
			out += ")"
		}
	}
	return out
}

func main() {
	cmd := "serve"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}
	var err error
	switch cmd {
	case "serve":
		err = serve()
	case "generate-key":
		err = generateKey()
	case "version":
		fmt.Println("vwsync-api", buildInfo())
	default:
		err = fmt.Errorf("unknown command %q (use: serve, generate-key, version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
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

func serve() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return err
	}
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if cfg.LogJSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	log := slog.New(handler)

	httpClient, err := vaultwarden.HTTPClient(cfg.VWCAFile, 30*time.Second)
	if err != nil {
		return err
	}
	vw := vaultwarden.New(httpClient, cfg.VWURL, vaultwarden.Credentials{
		ClientID:       cfg.VWClientID,
		ClientSecret:   cfg.VWClientSecret,
		MasterPassword: cfg.VWMasterPassword,
	}).WithLogger(log)
	// Falsche API-Key-Daten sollen den Start verhindern und nicht erst beim ersten Request auffallen.
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, err = vw.Login(startCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("vaultwarden login: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(server.Deps{Auth: cfg.APIKeys, Dir: vaultDir{vw}, Log: log, TrustProxy: cfg.TrustProxy}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute, // ein Sync oder Confirm kann mehrere Minuten dauern
		IdleTimeout:       60 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 1)
	go func() { errc <- srv.ListenAndServe() }()
	log.Info("listening", "addr", cfg.Listen, "version", buildInfo(), "confirm_enabled", cfg.VWMasterPassword != "")

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// generateKey gibt einen neuen Zugangsschlüssel für Aufrufer und den passenden Hash für die
// Konfiguration aus. Der Schlüssel wird nirgends gespeichert. Diese Ausgabe ist die einzige
// Gelegenheit, ihn zu sehen.
func generateKey() error {
	key, hash, err := auth.GenerateKey()
	if err != nil {
		return err
	}
	fmt.Println("API key for the caller. It is not stored and cannot be shown again:")
	fmt.Println(key)
	fmt.Println()
	fmt.Println("Line for the service configuration, for example /etc/vwsync-api/env:")
	fmt.Println("VWSYNC_API_KEY_HASH=" + hash)
	return nil
}
