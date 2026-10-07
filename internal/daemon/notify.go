// Package daemon spricht mit systemd über das sd_notify-Protokoll.
//
// Mit Type=notify wartet systemd beim Start auf READY=1. Erst dann gilt der Dienst als gestartet, und
// "systemctl start" kehrt zurück. STOPPING=1 und RELOADING=1 zeigen in "systemctl status" an, was der
// Dienst gerade tut, STATUS= liefert eine Zeile Klartext dazu. Mit WatchdogSec erwartet systemd
// regelmäßig WATCHDOG=1 und startet den Dienst neu, wenn die Meldung ausbleibt.
//
// Das Protokoll ist ein Datagramm an den Unix-Socket aus NOTIFY_SOCKET. Ohne systemd ist die Variable
// leer, und alle Meldungen werden still übergangen. Der Dienst läuft also auch außerhalb von systemd.
package daemon

import (
	"net"
	"os"
	"strconv"
	"time"
)

// Notifier sendet Zustandsmeldungen an den Dienstmanager.
type Notifier interface {
	Notify(state string) error
}

// Systemd ist der Notifier für systemd. Der leere Wert liest NOTIFY_SOCKET bei jedem Aufruf.
type Systemd struct{}

// Notify sendet state, etwa "READY=1" oder "STATUS=...". Mehrere Zuweisungen werden durch
// Zeilenumbrüche getrennt. Ohne NOTIFY_SOCKET passiert nichts.
func (Systemd) Notify(state string) error {
	socket := os.Getenv("NOTIFY_SOCKET")
	if socket == "" {
		return nil
	}
	// Ein führendes @ kennzeichnet einen Socket im abstrakten Namensraum von Linux.
	if socket[0] == '@' {
		socket = "\x00" + socket[1:]
	}
	conn, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte(state))
	return err
}

// WatchdogInterval liefert das Intervall, in dem WATCHDOG=1 gesendet werden muss, oder 0, wenn
// systemd keinen Watchdog für diesen Prozess erwartet. Gesendet wird mit halbem Abstand zur Frist,
// wie systemd es empfiehlt.
func WatchdogInterval() time.Duration {
	usec, err := strconv.ParseInt(os.Getenv("WATCHDOG_USEC"), 10, 64)
	if err != nil || usec <= 0 {
		return 0
	}
	if pid := os.Getenv("WATCHDOG_PID"); pid != "" && pid != strconv.Itoa(os.Getpid()) {
		return 0
	}
	return time.Duration(usec) * time.Microsecond / 2
}
