package server

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"

	"vwsync-api/internal/auth"
)

func readyEnv(t *testing.T, ping func(context.Context) error, stopping *atomic.Bool, logs io.Writer) env {
	t.Helper()
	keys, err := auth.ParseHashes(auth.HashKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	dir := newDir()
	h := New(Deps{Auth: keys, Dir: dir, Log: slog.New(slog.NewTextHandler(logs, nil)), Ping: ping, Stopping: stopping})
	return env{h, dir}
}

func TestReadyWhenVaultwardenAnswers(t *testing.T) {
	e := readyEnv(t, func(context.Context) error { return nil }, &atomic.Bool{}, io.Discard)
	rec := e.do("GET", "/readyz", "", "")
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"ready"`) {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}

func TestNotReadyWhenVaultwardenDoesNotAnswer(t *testing.T) {
	var logs bytes.Buffer
	e := readyEnv(t, func(context.Context) error { return errors.New("dial tcp 10.0.0.5:443: connection refused") }, &atomic.Bool{}, &logs)
	rec := e.do("GET", "/readyz", "", "")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "vaultwarden unreachable") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	// Die Einzelheiten stehen im Log, nicht in der Antwort, denn /readyz braucht keinen Schlüssel.
	if strings.Contains(rec.Body.String(), "10.0.0.5") || !strings.Contains(logs.String(), "10.0.0.5") {
		t.Fatalf("details must go to the log only: body=%s log=%s", rec.Body, logs.String())
	}
}

func TestNotReadyWhileStopping(t *testing.T) {
	var stopping atomic.Bool
	pinged := false
	e := readyEnv(t, func(context.Context) error { pinged = true; return nil }, &stopping, io.Discard)
	stopping.Store(true)
	rec := e.do("GET", "/readyz", "", "")
	if rec.Code != 503 || !strings.Contains(rec.Body.String(), "stopping") || pinged {
		t.Fatalf("%d %s pinged=%v", rec.Code, rec.Body, pinged)
	}
}

func TestHealthAndReadinessNeedNoKey(t *testing.T) {
	e := readyEnv(t, nil, nil, io.Discard)
	for _, path := range []string{"/healthz", "/readyz"} {
		if rec := e.do("GET", path, "", ""); rec.Code != 200 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}
