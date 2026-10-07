package app

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"vwsync-api/internal/auth"
	"vwsync-api/internal/config"
)

const testKey = "vwsk_AppTestKeyAppTestKeyAppTestKeyAppTestKeyA"

// fakeVW ist ein minimales Vaultwarden. Mit block hält es die Mitgliederliste an, bis block
// geschlossen wird, und meldet über started, dass ein Request wartet.
type fakeVW struct {
	rejectKey bool
	down      atomic.Bool // Logins scheitern mit 503, solange gesetzt
	block     chan struct{}
	started   chan struct{}
	once      sync.Once
}

func (f *fakeVW) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/identity/connect/token":
		if f.down.Load() {
			http.Error(w, "maintenance", http.StatusServiceUnavailable)
			return
		}
		if f.rejectKey {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(`{"access_token":"t","expires_in":7200,"Key":"K","PrivateKey":"P","Kdf":0,"KdfIterations":5}`))
	case "/alive":
		_, _ = w.Write([]byte(`"ok"`))
	case "/api/accounts/profile":
		_, _ = w.Write([]byte(`{"email":"me@x.io","organizations":[{"id":"o1","name":"Team","key":"k","type":0,"status":2}]}`))
	case "/api/organizations/o1/users":
		if f.block != nil {
			f.once.Do(func() { close(f.started) })
			<-f.block
		}
		_, _ = w.Write([]byte(`{"data":[]}`))
	default:
		http.NotFound(w, r)
	}
}

// recorder hält fest, was an systemd gemeldet wird.
type recorder struct{ ch chan string }

func (r *recorder) Notify(state string) error {
	r.ch <- state
	return nil
}

// waitFor liest Meldungen, bis eine want enthält.
func (r *recorder) waitFor(t *testing.T, want string) string {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-r.ch:
			if strings.Contains(got, want) {
				return got
			}
		case <-deadline:
			t.Fatalf("no notification containing %q", want)
		}
	}
}

type instance struct {
	t       *testing.T
	base    string
	signals chan os.Signal
	notes   *recorder
	errc    chan error
	logPath string
}

type setup struct {
	vw      *fakeVW
	vwURL   string
	logFile string
	wd      time.Duration
	retry   time.Duration
}

func start(t *testing.T, s setup) *instance {
	t.Helper()
	if s.vw == nil {
		s.vw = &fakeVW{}
	}
	if s.vwURL == "" {
		vw := httptest.NewServer(s.vw)
		t.Cleanup(vw.Close)
		s.vwURL = vw.URL
	}
	if s.logFile == "" {
		s.logFile = filepath.Join(t.TempDir(), "vwsync-api.log")
	}
	keys, err := auth.ParseHashes(auth.HashKey(testKey))
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	in := &instance{
		t:       t,
		base:    "http://" + ln.Addr().String(),
		signals: make(chan os.Signal, 4),
		notes:   &recorder{ch: make(chan string, 100)},
		errc:    make(chan error, 1),
		logPath: s.logFile,
	}
	opts := Options{
		Config: config.Config{
			APIKeys: keys, VWURL: s.vwURL, VWClientID: "user.1", VWClientSecret: "secret", LogFile: s.logFile,
		},
		Version:       "test",
		Signals:       in.signals,
		Notifier:      in.notes,
		Watchdog:      s.wd,
		RetryInterval: s.retry,
		Stderr:        os.Stderr,
		Listener:      ln,
	}
	go func() { in.errc <- Run(opts) }()
	return in
}

func (in *instance) get(path string) (int, error) {
	req, _ := http.NewRequest("GET", in.base+path, nil)
	req.Header.Set("Authorization", "Bearer "+testKey)
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

func (in *instance) expectStatus(path string, want int) {
	in.t.Helper()
	got, err := in.get(path)
	if err != nil || got != want {
		in.t.Fatalf("GET %s: %d %v, want %d", path, got, err, want)
	}
}

// stop sendet SIGTERM und wartet auf das Ende von Run.
func (in *instance) stop() error {
	in.t.Helper()
	in.signals <- syscall.SIGTERM
	select {
	case err := <-in.errc:
		return err
	case <-time.After(5 * time.Second):
		in.t.Fatal("Run did not return after SIGTERM")
		return nil
	}
}

func (in *instance) log() string {
	in.t.Helper()
	b, err := os.ReadFile(in.logPath)
	if err != nil {
		in.t.Fatal(err)
	}
	return string(b)
}

func TestStartReadyAndOrderlyStop(t *testing.T) {
	in := start(t, setup{})
	if got := in.notes.waitFor(t, "READY=1"); !strings.Contains(got, "STATUS=ready") {
		t.Fatalf("READY must come with a status: %q", got)
	}
	in.expectStatus("/healthz", 200)
	in.expectStatus("/readyz", 200)
	in.expectStatus("/v1/orgs", 200)

	if err := in.stop(); err != nil {
		t.Fatalf("an orderly stop must return nil: %v", err)
	}
	in.notes.waitFor(t, "STOPPING=1")
	if _, err := in.get("/healthz"); err == nil {
		t.Fatal("the port must be closed after the stop")
	}
	log := in.log()
	for _, want := range []string{"msg=listening", "msg=stopping", "signal=terminated", "msg=stopped"} {
		if !strings.Contains(log, want) {
			t.Errorf("log lacks %q:\n%s", want, log)
		}
	}
}

func TestARunningRequestFinishesBeforeTheServiceStops(t *testing.T) {
	vw := &fakeVW{block: make(chan struct{}), started: make(chan struct{})}
	in := start(t, setup{vw: vw, wd: 30 * time.Millisecond})
	in.notes.waitFor(t, "READY=1")

	result := make(chan int, 1)
	go func() {
		code, _ := in.get("/v1/orgs/o1/members")
		result <- code
	}()
	<-vw.started

	in.signals <- syscall.SIGTERM
	in.notes.waitFor(t, "STOPPING=1")
	// Der Watchdog muss auch während des Wartens weiter melden, sonst bricht systemd den Lauf ab.
	in.notes.waitFor(t, "WATCHDOG=1")
	select {
	case err := <-in.errc:
		t.Fatalf("Run returned while a request was still running: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	close(vw.block)
	if code := <-result; code != 200 {
		t.Fatalf("the running request must complete normally, got %d", code)
	}
	select {
	case err := <-in.errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after the last request finished")
	}
}

func TestASecondStopSignalAbortsRunningRequests(t *testing.T) {
	vw := &fakeVW{block: make(chan struct{}), started: make(chan struct{})}
	in := start(t, setup{vw: vw})
	// Nach start registriert, läuft also vor dem Schließen des Test-Vaultwarden, das sonst auf den
	// blockierten Request warten würde.
	t.Cleanup(func() { close(vw.block) })
	in.notes.waitFor(t, "READY=1")

	go func() { _, _ = in.get("/v1/orgs/o1/members") }()
	<-vw.started
	in.signals <- syscall.SIGTERM
	in.notes.waitFor(t, "STOPPING=1")
	if err := in.stop(); err != nil { // zweites SIGTERM
		t.Fatal(err)
	}
	if !strings.Contains(in.log(), "second stop signal") {
		t.Fatalf("the forced stop must be logged:\n%s", in.log())
	}
}

func TestReloadReopensTheLogFile(t *testing.T) {
	in := start(t, setup{})
	in.notes.waitFor(t, "READY=1")
	in.expectStatus("/healthz", 200)

	rotated := runtime.GOOS != "windows" // unter Windows lässt sich eine offene Datei nicht umbenennen
	if rotated {
		if err := os.Rename(in.logPath, in.logPath+".1"); err != nil {
			t.Fatal(err)
		}
	}
	in.signals <- syscall.SIGHUP
	in.notes.waitFor(t, "RELOADING=1")
	in.notes.waitFor(t, "READY=1")
	in.expectStatus("/healthz", 200)

	log := in.log()
	if !strings.Contains(log, "log file reopened") || !strings.Contains(log, "path=/healthz") {
		t.Fatalf("after the reload the service must log into the file at the configured path:\n%s", log)
	}
	if rotated {
		old, _ := os.ReadFile(in.logPath + ".1")
		if !strings.Contains(string(old), "msg=listening") || strings.Contains(string(old), "log file reopened") {
			t.Fatalf("the rotated file must keep the earlier lines only:\n%s", old)
		}
	}
	if err := in.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestARejectedAPIKeyPreventsTheStartWithTheConfigExitCode(t *testing.T) {
	in := start(t, setup{vw: &fakeVW{rejectKey: true}})
	select {
	case err := <-in.errc:
		var exit *ExitError
		if !errors.As(err, &exit) || exit.Code != ExitConfig {
			t.Fatalf("expected exit code %d, got %v", ExitConfig, err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	select {
	case note := <-in.notes.ch:
		t.Fatalf("nothing may be reported to systemd before a failed start, got %q", note)
	default:
	}
}

func TestAnUnreachableVaultwardenDoesNotPreventTheStart(t *testing.T) {
	gone := httptest.NewServer(http.NotFoundHandler())
	url := gone.URL
	gone.Close() // nichts lauscht mehr unter dieser Adresse

	in := start(t, setup{vwURL: url})
	if got := in.notes.waitFor(t, "READY=1"); !strings.Contains(got, "not reachable") {
		t.Fatalf("the status must say that Vaultwarden is not reachable: %q", got)
	}
	in.expectStatus("/healthz", 200)
	in.expectStatus("/readyz", 503)
	if code, _ := in.get("/v1/orgs"); code != http.StatusBadGateway {
		t.Fatalf("a call that needs Vaultwarden must report 502, got %d", code)
	}
	if err := in.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestAMissingLogDirectoryIsAConfigError(t *testing.T) {
	in := start(t, setup{logFile: filepath.Join(t.TempDir(), "missing", "vwsync-api.log")})
	select {
	case err := <-in.errc:
		var exit *ExitError
		if !errors.As(err, &exit) || exit.Code != ExitConfig || !strings.Contains(err.Error(), "VWSYNC_LOG_FILE") {
			t.Fatalf("%v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
}

func TestTheWatchdogReportsWhileTheServiceAnswers(t *testing.T) {
	in := start(t, setup{wd: 20 * time.Millisecond})
	in.notes.waitFor(t, "READY=1")
	in.notes.waitFor(t, "WATCHDOG=1")
	in.notes.waitFor(t, "WATCHDOG=1")
	if err := in.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestAnOccupiedPortIsNotAConfigError(t *testing.T) {
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = busy.Close() }()
	vw := httptest.NewServer(&fakeVW{})
	defer vw.Close()
	keys, _ := auth.ParseHashes(auth.HashKey(testKey))
	err = Run(Options{
		Config:  config.Config{Listen: busy.Addr().String(), APIKeys: keys, VWURL: vw.URL},
		Signals: make(chan os.Signal), Stderr: os.Stderr,
	})
	var exit *ExitError
	if err == nil || errors.As(err, &exit) {
		t.Fatalf("a busy port must fail with an ordinary error so that systemd may retry: %v", err)
	}
}

func TestAfterADisturbedStartTheStatusReturnsToReadyByItself(t *testing.T) {
	vw := &fakeVW{}
	vw.down.Store(true)
	in := start(t, setup{vw: vw, retry: 20 * time.Millisecond})
	if got := in.notes.waitFor(t, "READY=1"); !strings.Contains(got, "not reachable") {
		t.Fatalf("%q", got)
	}

	vw.down.Store(false) // Vaultwarden ist wieder da
	if got := in.notes.waitFor(t, "STATUS="); got != "STATUS=ready" {
		t.Fatalf("the status must go back to ready: %q", got)
	}
	if !strings.Contains(in.log(), "vaultwarden is reachable again") {
		t.Fatal("the recovery must be logged")
	}

	// Ein reload danach meldet den aktuellen Status, nicht den vom Start.
	in.signals <- syscall.SIGHUP
	if got := in.notes.waitFor(t, "READY=1"); got != "READY=1\nSTATUS=ready" {
		t.Fatalf("reload reported a stale status: %q", got)
	}
	if err := in.stop(); err != nil {
		t.Fatal(err)
	}
}
