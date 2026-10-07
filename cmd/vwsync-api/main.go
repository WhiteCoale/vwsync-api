// Command vwsync-api ist ein REST-Dienst, der Organisationen und Mitglieder in Vaultwarden abgleicht.
//
//	vwsync-api                startet den Dienst (wie "serve")
//	vwsync-api generate-key   erzeugt einen Zugangsschlüssel für Aufrufer und den Hash für die Konfiguration
//	vwsync-api version        gibt die Version aus, aus der dieses Binary gebaut wurde
//
// Exit-Codes von serve: 0 nach geordnetem Stopp, 78 bei einem Fehler in der Konfiguration (die Unit
// startet dann nicht neu), 1 bei jedem anderen Fehler.
package main

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"vwsync-api/internal/app"
	"vwsync-api/internal/auth"
	"vwsync-api/internal/config"
	"vwsync-api/internal/daemon"
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
		var exit *app.ExitError
		if errors.As(err, &exit) {
			os.Exit(exit.Code)
		}
		os.Exit(1)
	}
}

// serve liest die Konfiguration und übergibt an app.Run. Die Signale kommen über einen Kanal, damit
// Run sie der Reihe nach behandelt: SIGHUP lädt neu, SIGTERM und SIGINT beenden den Dienst.
func serve() error {
	cfg, err := config.FromEnv()
	if err != nil {
		return &app.ExitError{Code: app.ExitConfig, Err: err}
	}
	signals := make(chan os.Signal, 4)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT, syscall.SIGHUP)
	defer signal.Stop(signals)

	return app.Run(app.Options{
		Config:   cfg,
		Version:  buildInfo(),
		Signals:  signals,
		Notifier: daemon.Systemd{},
		Watchdog: daemon.WatchdogInterval(),
		Stderr:   os.Stderr,
	})
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
