// Package config liest die Konfiguration des Dienstes aus Umgebungsvariablen.
// Unter systemd stammen sie aus einer EnvironmentFile. Eine eigene Konfigurationsdatei mit Secrets
// gibt es nicht.
package config

import (
	"errors"
	"log/slog"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"vwsync-api/internal/auth"
)

type Config struct {
	Listen string

	// APIKeys sind die Hashes der Zugangsschlüssel, die Aufrufer vorlegen dürfen.
	APIKeys *auth.Keys
	// TrustProxy lässt den Dienst die Adresse des Aufrufers aus X-Real-IP lesen, für die Logzeile eines
	// abgewiesenen Requests. Der Header gilt nur für Requests von der Loopback-Schnittstelle.
	TrustProxy bool

	// LogLevel ist debug, info, warn oder error. LogJSON stellt das Logformat von Text auf JSON um.
	LogLevel slog.Level
	LogJSON  bool

	// Vaultwarden.
	VWURL          string
	VWClientID     string
	VWClientSecret string
	// VWMasterPassword ist optional. Ohne Master-Passwort funktioniert alles außer confirm und dem
	// Anlegen von Organisationen.
	VWMasterPassword string
	// VWCAFile ist eine optionale PEM-Datei mit zusätzlichen Zertifizierungsstellen für VW_URL, für
	// einen Vaultwarden-Server, dessen Zertifikat von einer internen CA stammt.
	VWCAFile string
}

// FromEnv liest und prüft die Konfiguration. Alle Probleme werden gemeinsam gemeldet.
func FromEnv() (Config, error) {
	var problems []string
	req := func(name string) string {
		v := os.Getenv(name)
		if v == "" {
			problems = append(problems, name+" is missing")
		}
		return v
	}

	c := Config{
		Listen:           envOr("VWSYNC_LISTEN", "127.0.0.1:8080"),
		VWURL:            strings.TrimRight(req("VW_URL"), "/"),
		VWClientID:       req("VW_CLIENT_ID"),
		VWClientSecret:   req("VW_CLIENT_SECRET"),
		VWMasterPassword: os.Getenv("VW_MASTER_PASSWORD"),
		VWCAFile:         os.Getenv("VW_CA_FILE"),
	}
	if c.VWURL != "" {
		if err := checkVaultwardenURL(c.VWURL); err != nil {
			problems = append(problems, err.Error())
		}
	}

	if hashes := req("VWSYNC_API_KEY_HASH"); hashes != "" {
		keys, err := auth.ParseHashes(hashes)
		if err != nil {
			problems = append(problems, "VWSYNC_API_KEY_HASH: "+err.Error())
		}
		c.APIKeys = keys
	}

	if v := os.Getenv("VWSYNC_TRUST_PROXY"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			problems = append(problems, "VWSYNC_TRUST_PROXY must be true or false")
		}
		c.TrustProxy = b
	}

	if v := os.Getenv("VWSYNC_LOG_LEVEL"); v != "" {
		if err := c.LogLevel.UnmarshalText([]byte(v)); err != nil || strings.ContainsAny(v, "+-0123456789") {
			problems = append(problems, "VWSYNC_LOG_LEVEL must be debug, info, warn or error")
		}
	}
	switch v := os.Getenv("VWSYNC_LOG_FORMAT"); v {
	case "", "text":
	case "json":
		c.LogJSON = true
	default:
		problems = append(problems, "VWSYNC_LOG_FORMAT must be text or json")
	}

	if len(problems) > 0 {
		return Config{}, errors.New("invalid configuration: " + strings.Join(problems, "; "))
	}
	return c, nil
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// checkVaultwardenURL verlangt HTTPS. Der Dienst sendet API-Key, Access-Token und Schlüsselmaterial
// des Kontos an diese Adresse, in der Regel ein anderer Server. Unverschlüsseltes HTTP ist nur für den
// lokalen Rechner erlaubt, für Entwicklung und Tests.
func checkVaultwardenURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return errors.New("VW_URL must be a URL like https://vault.example.com")
	}
	if u.Scheme == "https" {
		return nil
	}
	host := u.Hostname()
	if host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return errors.New("VW_URL must use https, plain http is only allowed for localhost")
}
