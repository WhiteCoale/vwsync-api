// Command vwsync-api is a REST service that syncs Vaultwarden organization members.
//
//	vwsync-api                run the service (same as "serve")
//	vwsync-api hash-password  print a bcrypt hash for VWSYNC_PASSWORD_HASH
//	vwsync-api version        print the version this binary was built from
package main

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"vwsync-api/internal/auth"
	"vwsync-api/internal/config"
	"vwsync-api/internal/reconcile"
	"vwsync-api/internal/server"
	"vwsync-api/internal/vaultwarden"
)

// version is set at build time: -ldflags "-X main.version=v1.2.3". Without it the binary still
// reports the commit it was built from, taken from the build info Go embeds.
var version = "dev"

// buildInfo returns the version and, when built inside a git checkout, the commit.
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
	case "hash-password":
		err = hashPassword()
	case "version":
		fmt.Println("vwsync-api", buildInfo())
	default:
		err = fmt.Errorf("unknown command %q (use: serve, hash-password, version)", cmd)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// vaultDir adapts the Vaultwarden client to server.Directory. The only gap is the return type of
// Vault: the server wants the small reconcile.OrgKeys interface, the client returns *crypto.KeyVault.
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
	a, err := auth.New(cfg.User, cfg.PasswordHash, cfg.JWTSecret, cfg.TokenTTL)
	if err != nil {
		return err
	}
	opts := &slog.HandlerOptions{Level: cfg.LogLevel}
	var handler slog.Handler = slog.NewTextHandler(os.Stderr, opts)
	if cfg.LogJSON {
		handler = slog.NewJSONHandler(os.Stderr, opts)
	}
	log := slog.New(handler)

	vw := vaultwarden.New(&http.Client{Timeout: 30 * time.Second}, cfg.VWURL, vaultwarden.Credentials{
		ClientID:       cfg.VWClientID,
		ClientSecret:   cfg.VWClientSecret,
		MasterPassword: cfg.VWMasterPassword,
	}).WithLogger(log)
	// Fail at startup on wrong API-key credentials instead of on the first request.
	startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	_, err = vw.Login(startCtx)
	cancel()
	if err != nil {
		return fmt.Errorf("vaultwarden login: %w", err)
	}

	srv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           server.New(server.Deps{Auth: a, Dir: vaultDir{vw}, Log: log, TrustProxy: cfg.TrustProxy}),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      11 * time.Minute, // a sync or confirm run may take several minutes
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

func hashPassword() error {
	var pw string
	if term.IsTerminal(int(os.Stdin.Fd())) {
		fmt.Fprint(os.Stderr, "Password: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return err
		}
		pw = string(b)
	} else {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return errors.New("no password on stdin")
		}
		pw = strings.TrimRight(line, "\r\n")
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}
