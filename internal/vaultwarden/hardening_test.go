package vaultwarden

import (
	"bytes"
	"context"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestTruncateNeverSplitsACharacter(t *testing.T) {
	// 150 Zwei-Byte-Buchstaben sind 300 Byte. Ein ASCII-Byte davor legt den Schnitt in ein Zeichen.
	s := "a" + strings.Repeat("ä", 150)
	got := truncate(s, 300)
	if !utf8.ValidString(got) || len(got) > 300 {
		t.Fatalf("invalid or too long: %d bytes, valid=%v", len(got), utf8.ValidString(got))
	}
	if got := truncate("short", 300); got != "short" {
		t.Fatal(got)
	}
	if got := truncate("😀😀😀", 5); !utf8.ValidString(got) || got != "😀" {
		t.Fatalf("%q", got)
	}
}

func TestDeviceIDIsStableAndUUIDShaped(t *testing.T) {
	a, b := deviceID("user.1"), deviceID("user.1")
	if a != b || a == deviceID("user.2") {
		t.Fatal("device id must be stable per client id and differ between accounts")
	}
	if !regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(a) {
		t.Fatalf("not UUID shaped: %s", a)
	}
}

func TestDebugLogShowsCallsButNeverSecrets(t *testing.T) {
	var logs bytes.Buffer
	c, f := newFake(t, good)
	c.WithLogger(slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug})))
	f.handlers["GET /api/accounts/profile"] = `{"email":"a@x.io"}`
	if _, err := c.SelfEmail(context.Background()); err != nil {
		t.Fatal(err)
	}
	out := logs.String()
	if !strings.Contains(out, "path=/identity/connect/token") || !strings.Contains(out, "path=/api/accounts/profile") || !strings.Contains(out, "status=200") {
		t.Fatalf("calls are not logged:\n%s", out)
	}
	for _, secret := range []string{"s3cret", "user.1", "Bearer"} {
		if strings.Contains(out, secret) {
			t.Fatalf("%q leaked into the debug log:\n%s", secret, out)
		}
	}
	// Das Access-Token des Testservers lautet "tok". Geprüft wird das ganze Wort, denn "token" steht
	// in einem Pfad.
	if regexp.MustCompile(`\btok\b`).MatchString(out) {
		t.Fatalf("access token leaked into the debug log:\n%s", out)
	}
}

func TestLoginWithOddKeyFieldsStillWorksButConfirmSaysWhy(t *testing.T) {
	c, f := newFake(t, Credentials{ClientID: "user.1", ClientSecret: "s3cret", MasterPassword: "pw"})
	f.login["KdfIterations"] = "600000" // eine Zeichenkette, wo eine Zahl erwartet wird
	f.handlers["GET /api/accounts/profile"] = `{"email":"a@x.io"}`

	ld, err := c.Login(context.Background())
	if err != nil || ld.Problem == "" {
		t.Fatalf("login must succeed and note the problem: %+v %v", ld, err)
	}
	if _, err := c.SelfEmail(context.Background()); err != nil {
		t.Fatalf("everything that needs no keys must keep working: %v", err)
	}
	_, err = c.Vault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "KdfIterations") {
		t.Fatalf("unlock must name the odd field: %v", err)
	}
}

func TestVaultSaysWhenTheLoginHasNoKeyMaterial(t *testing.T) {
	c, f := newFake(t, Credentials{ClientID: "user.1", ClientSecret: "s3cret", MasterPassword: "pw"})
	delete(f.login, "Key")
	delete(f.login, "PrivateKey")
	_, err := c.Vault(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no key material") {
		t.Fatalf("%v", err)
	}
}
