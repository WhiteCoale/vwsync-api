package config

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func valid(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"VWSYNC_USER": "sync", "VWSYNC_PASSWORD_HASH": "$2a$12$x", "VWSYNC_JWT_SECRET": strings.Repeat("s", 32),
		"VW_URL": "https://vault.example.com/", "VW_CLIENT_ID": "user.1", "VW_CLIENT_SECRET": "secret",
	} {
		t.Setenv(k, v)
	}
	for _, k := range []string{"VWSYNC_LISTEN", "VWSYNC_TOKEN_TTL", "VWSYNC_TRUST_PROXY", "VWSYNC_LOG_LEVEL", "VWSYNC_LOG_FORMAT", "VW_MASTER_PASSWORD"} {
		t.Setenv(k, "")
	}
}

func TestDefaults(t *testing.T) {
	valid(t)
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.TokenTTL != 15*time.Minute || c.TrustProxy || c.LogLevel != slog.LevelInfo || c.LogJSON {
		t.Fatalf("%+v", c)
	}
	if c.VWURL != "https://vault.example.com" {
		t.Fatalf("trailing slash kept: %q", c.VWURL)
	}
}

func TestOverrides(t *testing.T) {
	valid(t)
	t.Setenv("VWSYNC_LISTEN", "127.0.0.1:9000")
	t.Setenv("VWSYNC_TOKEN_TTL", "2h")
	t.Setenv("VWSYNC_TRUST_PROXY", "true")
	t.Setenv("VWSYNC_LOG_LEVEL", "debug")
	t.Setenv("VWSYNC_LOG_FORMAT", "json")
	t.Setenv("VW_MASTER_PASSWORD", "pw")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9000" || c.TokenTTL != 2*time.Hour || !c.TrustProxy || c.LogLevel != slog.LevelDebug || !c.LogJSON || c.VWMasterPassword != "pw" {
		t.Fatalf("%+v", c)
	}
}

func TestAllProblemsAreReportedTogether(t *testing.T) {
	valid(t)
	t.Setenv("VWSYNC_USER", "")
	t.Setenv("VW_CLIENT_SECRET", "")
	t.Setenv("VWSYNC_JWT_SECRET", "short")
	t.Setenv("VWSYNC_TOKEN_TTL", "30s")
	t.Setenv("VWSYNC_TRUST_PROXY", "maybe")
	t.Setenv("VWSYNC_LOG_LEVEL", "chatty")
	t.Setenv("VWSYNC_LOG_FORMAT", "xml")
	_, err := FromEnv()
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"VWSYNC_USER is missing", "VW_CLIENT_SECRET is missing", "at least 32", "VWSYNC_TOKEN_TTL", "VWSYNC_TRUST_PROXY", "VWSYNC_LOG_LEVEL", "VWSYNC_LOG_FORMAT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
}

func TestLogLevelRejectsOffsets(t *testing.T) {
	// slog would accept "info+2"; the config documents four plain names only.
	valid(t)
	t.Setenv("VWSYNC_LOG_LEVEL", "info+2")
	if _, err := FromEnv(); err == nil {
		t.Fatal("offset accepted")
	}
}
