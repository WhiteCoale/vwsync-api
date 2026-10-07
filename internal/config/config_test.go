package config

import (
	"log/slog"
	"strings"
	"testing"

	"vwsync-api/internal/auth"
)

const testKey = "vwsk_ConfigTestKeyConfigTestKeyConfigTestKey1"

func valid(t *testing.T) {
	t.Helper()
	for k, v := range map[string]string{
		"VWSYNC_API_KEY_HASH": auth.HashKey(testKey),
		"VW_URL":              "https://vault.example.com/",
		"VW_CLIENT_ID":        "user.1",
		"VW_CLIENT_SECRET":    "secret",
	} {
		t.Setenv(k, v)
	}
	for _, k := range []string{"VWSYNC_LISTEN", "VWSYNC_TRUST_PROXY", "VWSYNC_LOG_LEVEL", "VWSYNC_LOG_FORMAT", "VW_MASTER_PASSWORD", "VW_CA_FILE", "VWSYNC_LOG_FILE"} {
		t.Setenv(k, "")
	}
}

func TestDefaults(t *testing.T) {
	valid(t)
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:8080" || c.TrustProxy || c.LogLevel != slog.LevelInfo || c.LogJSON {
		t.Fatalf("%+v", c)
	}
	if c.VWURL != "https://vault.example.com" {
		t.Fatalf("trailing slash kept: %q", c.VWURL)
	}
	if !c.APIKeys.Verify(testKey) || c.APIKeys.Verify("vwsk_other") {
		t.Fatal("the configured key hash does not accept exactly the configured key")
	}
}

func TestOverrides(t *testing.T) {
	valid(t)
	t.Setenv("VWSYNC_LISTEN", "127.0.0.1:9000")
	t.Setenv("VWSYNC_TRUST_PROXY", "true")
	t.Setenv("VWSYNC_LOG_LEVEL", "debug")
	t.Setenv("VWSYNC_LOG_FORMAT", "json")
	t.Setenv("VW_MASTER_PASSWORD", "pw")
	c, err := FromEnv()
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != "127.0.0.1:9000" || !c.TrustProxy || c.LogLevel != slog.LevelDebug || !c.LogJSON || c.VWMasterPassword != "pw" {
		t.Fatalf("%+v", c)
	}
}

func TestSeveralKeyHashesAreAccepted(t *testing.T) {
	valid(t)
	_, secondHash, _ := auth.GenerateKey()
	t.Setenv("VWSYNC_API_KEY_HASH", auth.HashKey(testKey)+","+secondHash)
	c, err := FromEnv()
	if err != nil || !c.APIKeys.Verify(testKey) {
		t.Fatal(err)
	}
}

func TestAllProblemsAreReportedTogether(t *testing.T) {
	valid(t)
	t.Setenv("VWSYNC_API_KEY_HASH", "not-a-hash")
	t.Setenv("VW_CLIENT_SECRET", "")
	t.Setenv("VWSYNC_TRUST_PROXY", "maybe")
	t.Setenv("VWSYNC_LOG_LEVEL", "chatty")
	t.Setenv("VWSYNC_LOG_FORMAT", "xml")
	_, err := FromEnv()
	if err == nil {
		t.Fatal("accepted")
	}
	for _, want := range []string{"VWSYNC_API_KEY_HASH", "VW_CLIENT_SECRET is missing", "VWSYNC_TRUST_PROXY", "VWSYNC_LOG_LEVEL", "VWSYNC_LOG_FORMAT"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message lacks %q: %v", want, err)
		}
	}
}

func TestAMissingKeyHashPointsToGenerateKey(t *testing.T) {
	valid(t)
	t.Setenv("VWSYNC_API_KEY_HASH", "")
	_, err := FromEnv()
	if err == nil || !strings.Contains(err.Error(), "VWSYNC_API_KEY_HASH is missing") {
		t.Fatalf("%v", err)
	}
}

func TestTheKeyItselfInsteadOfItsHashIsRejectedWithoutEchoingIt(t *testing.T) {
	// Der wahrscheinlichste Fehler ist, den Schlüssel statt des Hashs einzutragen. Das muss scheitern,
	// und die Meldung darf den Schlüssel nicht wiederholen.
	valid(t)
	key, _, _ := auth.GenerateKey()
	t.Setenv("VWSYNC_API_KEY_HASH", key)
	_, err := FromEnv()
	if err == nil || strings.Contains(err.Error(), key) {
		t.Fatalf("%v", err)
	}
}

func TestLogLevelRejectsOffsets(t *testing.T) {
	// slog würde "info+2" akzeptieren, dokumentiert sind aber nur die vier einfachen Namen.
	valid(t)
	t.Setenv("VWSYNC_LOG_LEVEL", "info+2")
	if _, err := FromEnv(); err == nil {
		t.Fatal("offset accepted")
	}
}

func TestLogFileIsPassedThrough(t *testing.T) {
	valid(t)
	c, err := FromEnv()
	if err != nil || c.LogFile != "" {
		t.Fatalf("without VWSYNC_LOG_FILE the log goes to stderr: %q %v", c.LogFile, err)
	}
	t.Setenv("VWSYNC_LOG_FILE", "/var/log/vwsync-api/vwsync-api.log")
	if c, err = FromEnv(); err != nil || c.LogFile != "/var/log/vwsync-api/vwsync-api.log" {
		t.Fatalf("%q %v", c.LogFile, err)
	}
}
