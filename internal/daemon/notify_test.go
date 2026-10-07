package daemon

import (
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
	"time"
)

func TestNotifyWithoutSystemdDoesNothing(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	if err := (Systemd{}).Notify("READY=1"); err != nil {
		t.Fatal(err)
	}
}

func listen(t *testing.T, name string) *net.UnixConn {
	t.Helper()
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: name, Net: "unixgram"})
	if err != nil {
		t.Skipf("unixgram sockets are not available here: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func receive(t *testing.T, conn *net.UnixConn) string {
	t.Helper()
	buf := make([]byte, 4096)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	return string(buf[:n])
}

func TestNotifyReachesTheSocket(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("systemd and unixgram sockets exist only on Linux")
	}
	path := filepath.Join(t.TempDir(), "notify.sock")
	conn := listen(t, path)
	t.Setenv("NOTIFY_SOCKET", path)
	if err := (Systemd{}).Notify("READY=1\nSTATUS=ready"); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, conn); got != "READY=1\nSTATUS=ready" {
		t.Fatalf("%q", got)
	}
}

func TestNotifyUsesTheAbstractNamespace(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the abstract socket namespace exists only on Linux")
	}
	name := "vwsync-test-" + strconv.Itoa(os.Getpid())
	conn := listen(t, "\x00"+name)
	t.Setenv("NOTIFY_SOCKET", "@"+name)
	if err := (Systemd{}).Notify("WATCHDOG=1"); err != nil {
		t.Fatal(err)
	}
	if got := receive(t, conn); got != "WATCHDOG=1" {
		t.Fatalf("%q", got)
	}
}

func TestWatchdogInterval(t *testing.T) {
	pid := strconv.Itoa(os.Getpid())
	cases := []struct {
		usec, pid string
		want      time.Duration
	}{
		{"", "", 0},
		{"garbage", "", 0},
		{"0", "", 0},
		{"60000000", "", 30 * time.Second},  // WatchdogSec=60, gesendet wird alle 30 Sekunden
		{"60000000", pid, 30 * time.Second}, // für diesen Prozess bestimmt
		{"60000000", "1", 0},                // für einen anderen Prozess bestimmt
	}
	for _, c := range cases {
		t.Setenv("WATCHDOG_USEC", c.usec)
		t.Setenv("WATCHDOG_PID", c.pid)
		if got := WatchdogInterval(); got != c.want {
			t.Errorf("WATCHDOG_USEC=%q WATCHDOG_PID=%q: got %v, want %v", c.usec, c.pid, got, c.want)
		}
	}
}
