package logfile

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path) //nolint:gosec // Pfad aus t.TempDir
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWritesAreAppendedAndSurviveReopening(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	if err := os.WriteFile(path, []byte("earlier line\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	_, _ = l.Write([]byte("first\n"))
	if err := l.Reopen(); err != nil {
		t.Fatal(err)
	}
	_, _ = l.Write([]byte("second\n"))
	if got := read(t, path); got != "earlier line\nfirst\nsecond\n" {
		t.Fatalf("existing content must be kept and new lines appended: %q", got)
	}
}

func TestReopenFollowsARotatedFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename a file that is open, logrotate does not exist there")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "service.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	_, _ = l.Write([]byte("before rotation\n"))

	// So rotiert logrotate: umbenennen, danach den Dienst neu öffnen lassen.
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	_, _ = l.Write([]byte("still old file\n"))
	if err := l.Reopen(); err != nil {
		t.Fatal(err)
	}
	_, _ = l.Write([]byte("after rotation\n"))

	if got := read(t, path+".1"); got != "before rotation\nstill old file\n" {
		t.Fatalf("rotated file: %q", got)
	}
	if got := read(t, path); got != "after rotation\n" {
		t.Fatalf("new file: %q", got)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("new file must be created with 0640: %v %v", info.Mode(), err)
	}
}

func TestAFailedReopenKeepsWritingToTheOldFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	l.path = filepath.Join(t.TempDir(), "missing-dir", "service.log") // Verzeichnis existiert nicht
	if err := l.Reopen(); err == nil {
		t.Fatal("reopening into a missing directory must fail")
	}
	if _, err := l.Write([]byte("kept\n")); err != nil {
		t.Fatalf("writing must go on after a failed reopen: %v", err)
	}
	if got := read(t, path); got != "kept\n" {
		t.Fatalf("%q", got)
	}
}

func TestConcurrentWritesDuringReopenLoseNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_, _ = l.Write([]byte("line\n"))
			}
		}()
	}
	for i := 0; i < 20; i++ {
		if err := l.Reopen(); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
	_ = l.Close()
	if n := strings.Count(read(t, path), "line\n"); n != 1600 {
		t.Fatalf("expected 1600 lines, got %d", n)
	}
}

func TestOpenFailsClearlyForAMissingDirectory(t *testing.T) {
	_, err := Open(filepath.Join(t.TempDir(), "nope", "service.log"))
	if err == nil || !strings.Contains(err.Error(), "opening log file") {
		t.Fatalf("%v", err)
	}
}

// clock ist eine steuerbare Uhr für die Prüfung auf Rotation.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func openWithClock(t *testing.T, path string) (*File, *clock) {
	t.Helper()
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	c := &clock{t: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	l.now = c.now
	l.lastCheck = c.t
	return l, c
}

func TestARotatedFileIsFollowedEvenWithoutReload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot rename a file that is open")
	}
	path := filepath.Join(t.TempDir(), "service.log")
	l, c := openWithClock(t, path)
	_, _ = l.Write([]byte("before\n"))

	if err := os.Rename(path, path+".1"); err != nil { // logrotate, aber kein reload
		t.Fatal(err)
	}
	c.advance(5 * time.Second)
	_, _ = l.Write([]byte("within the interval\n"))
	c.advance(6 * time.Second) // jetzt mehr als zehn Sekunden seit der letzten Prüfung
	_, _ = l.Write([]byte("after the check\n"))

	if got := read(t, path+".1"); got != "before\nwithin the interval\n" {
		t.Fatalf("rotated file: %q", got)
	}
	if got := read(t, path); got != "after the check\n" {
		t.Fatalf("the service must follow the rotation by itself: %q", got)
	}
}

func TestADeletedFileIsCreatedAgain(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot delete a file that is open")
	}
	path := filepath.Join(t.TempDir(), "service.log")
	l, c := openWithClock(t, path)
	_, _ = l.Write([]byte("gone\n"))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	c.advance(11 * time.Second)
	_, _ = l.Write([]byte("back\n"))
	if got := read(t, path); got != "back\n" {
		t.Fatalf("%q", got)
	}
}

func TestWithoutRotationTheSameFileIsKept(t *testing.T) {
	path := filepath.Join(t.TempDir(), "service.log")
	l, c := openWithClock(t, path)
	before := l.f
	for i := 0; i < 5; i++ {
		c.advance(11 * time.Second)
		_, _ = l.Write([]byte("line\n"))
	}
	if l.f != before {
		t.Fatal("the file must not be reopened when nothing was rotated")
	}
	if got := read(t, path); got != strings.Repeat("line\n", 5) {
		t.Fatalf("%q", got)
	}
}
