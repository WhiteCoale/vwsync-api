// Package logfile schreibt das Log in eine Datei, die sich im laufenden Betrieb neu öffnen lässt.
//
// logrotate benennt die Datei um und legt eine neue an. Ein Prozess, der die alte Datei offen hält,
// schriebe ohne erneutes Öffnen weiter in die umbenannte Datei. Zwei Wege verhindern das:
//
//   - Reopen öffnet die Datei sofort neu. Der Dienst ruft es bei SIGHUP auf, also bei
//     "systemctl reload vwsync-api", und die logrotate-Vorlage löst das nach jeder Rotation aus.
//   - Write prüft außerdem höchstens alle zehn Sekunden, ob unter dem Pfad noch dieselbe Datei liegt,
//     und öffnet sonst selbst neu. Die Rotation funktioniert damit auch, wenn der reload nicht
//     ankommt, etwa weil eine SELinux-Regel logrotate den Aufruf von systemctl verbietet. Zeilen aus
//     den Sekunden bis zur Prüfung landen noch in der umbenannten Datei, verloren geht keine.
package logfile

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// checkInterval ist der Abstand, in dem Write prüft, ob die Datei rotiert wurde.
const checkInterval = 10 * time.Second

// File ist ein io.Writer auf eine Logdatei. Er ist sicher für gleichzeitige Aufrufe.
type File struct {
	path string
	now  func() time.Time

	mu        sync.Mutex // schützt f und lastCheck
	f         *os.File
	lastCheck time.Time
}

// Open öffnet die Logdatei zum Anhängen und legt sie bei Bedarf an. Das Verzeichnis muss existieren,
// unter systemd legt LogsDirectory es an.
func Open(path string) (*File, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	l := &File{path: abs, now: time.Now}
	if l.f, err = openFile(abs); err != nil {
		return nil, err
	}
	l.lastCheck = l.now()
	return l, nil
}

// Path ist der absolute Pfad der Logdatei.
func (l *File) Path() string { return l.path }

// Write hängt p an die Logdatei an. Ist seit der letzten Prüfung genug Zeit vergangen, folgt es vorher
// einer Rotation.
func (l *File) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := l.now(); now.Sub(l.lastCheck) >= checkInterval {
		l.lastCheck = now
		l.followRotation()
	}
	return l.f.Write(p)
}

// followRotation öffnet die Datei neu, wenn unter dem Pfad keine oder eine andere Datei liegt als die
// offene. Scheitert das Öffnen, bleibt die bisherige Datei in Gebrauch. Der Aufrufer hält l.mu.
func (l *File) followRotation() {
	open, err1 := l.f.Stat()
	onDisk, err2 := os.Stat(l.path)
	if err1 == nil && err2 == nil && os.SameFile(open, onDisk) {
		return
	}
	f, err := openFile(l.path)
	if err != nil {
		return
	}
	old := l.f
	l.f = f
	_ = old.Close()
}

// Reopen öffnet die Datei unter ihrem Pfad neu. Scheitert das, schreibt der Dienst weiter in die bisher
// offene Datei, damit keine Logzeilen verloren gehen.
func (l *File) Reopen() error {
	f, err := openFile(l.path)
	if err != nil {
		return err
	}
	l.mu.Lock()
	old := l.f
	l.f = f
	l.mu.Unlock()
	return old.Close()
}

// Close schließt die Datei.
func (l *File) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

func openFile(path string) (*os.File, error) {
	// 0640: lesbar für den Dienst und seine Gruppe, etwa für logrotate oder Admins in der Gruppe.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o640) //nolint:gosec // der Pfad stammt aus der Konfiguration des Betreibers
	if err != nil {
		return nil, fmt.Errorf("opening log file: %w", err)
	}
	return f, nil
}
