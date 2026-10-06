// Package config reads the service configuration from environment variables.
// With systemd they come from an EnvironmentFile; there is no config file with secrets.
package config

import (
	"errors"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Listen string

	// Service login (the single user of this API).
	User         string
	PasswordHash string // bcrypt
	JWTSecret    []byte
	TokenTTL     time.Duration
	// TrustProxy makes the service read the client IP from X-Real-IP. Enable only behind a proxy
	// that sets the header, otherwise anyone could spoof it and dodge the login rate limit.
	TrustProxy bool

	// LogLevel is debug, info, warn or error. LogJSON switches the log format from text to JSON.
	LogLevel slog.Level
	LogJSON  bool

	// Vaultwarden.
	VWURL          string
	VWClientID     string
	VWClientSecret string
	// VWMasterPassword is optional; without it everything works except confirm.
	VWMasterPassword string
}

// FromEnv reads and validates the configuration. All problems are reported together.
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
		User:             req("VWSYNC_USER"),
		PasswordHash:     req("VWSYNC_PASSWORD_HASH"),
		VWURL:            strings.TrimRight(req("VW_URL"), "/"),
		VWClientID:       req("VW_CLIENT_ID"),
		VWClientSecret:   req("VW_CLIENT_SECRET"),
		VWMasterPassword: os.Getenv("VW_MASTER_PASSWORD"),
	}

	secret := req("VWSYNC_JWT_SECRET")
	if secret != "" && len(secret) < 32 {
		problems = append(problems, "VWSYNC_JWT_SECRET must be at least 32 characters")
	}
	c.JWTSecret = []byte(secret)

	c.TokenTTL = 15 * time.Minute
	if v := os.Getenv("VWSYNC_TOKEN_TTL"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil || d < time.Minute || d > 24*time.Hour {
			problems = append(problems, "VWSYNC_TOKEN_TTL must be a duration between 1m and 24h")
		} else {
			c.TokenTTL = d
		}
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
