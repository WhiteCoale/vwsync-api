// Package auth prüft den Zugangsschlüssel, den Aufrufer vorlegen.
//
// Der Dienst hat keine Benutzer und keinen Login. Ein Aufrufer besitzt einen langen Zufallsschlüssel
// und sendet ihn mit jedem Request als "Authorization: Bearer <Schlüssel>". Der Dienst speichert nur
// den SHA-256-Hash des Schlüssels, eine geleakte Konfigurationsdatei verrät ihn also nicht. Der
// Schlüssel hat 256 Bit Entropie. Deshalb genügt ein schneller Hash. Es gibt nichts durchzuprobieren,
// und ein langsamer Passwort-Hash wäre überflüssig.
package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// keyPrefix kennzeichnet den Schlüssel, damit Secret-Scanner und Menschen ihn erkennen.
const keyPrefix = "vwsk_"

// GenerateKey erzeugt einen neuen Zufallsschlüssel und den Hash, der dafür konfiguriert wird.
func GenerateKey() (key, hash string, err error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", "", err
	}
	key = keyPrefix + base64.RawURLEncoding.EncodeToString(raw)
	return key, HashKey(key), nil
}

// HashKey liefert den SHA-256 eines Schlüssels in Hex. In dieser Form steht er in der Konfiguration.
func HashKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

// Keys ist die Menge der akzeptierten Schlüssel, gespeichert als Hashes. Mehrere Schlüssel gelten
// gleichzeitig, damit sich ein Schlüssel ohne Unterbrechung austauschen lässt. Dazu wird der neue Hash
// eingetragen, der Aufrufer umgestellt und danach der alte Hash entfernt.
type Keys struct {
	hashes [][sha256.Size]byte
}

// ParseHashes liest eine kommagetrennte Liste von SHA-256-Hashes in Hex.
func ParseHashes(list string) (*Keys, error) {
	var k Keys
	for _, part := range strings.Split(list, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		raw, err := hex.DecodeString(part)
		if err != nil || len(raw) != sha256.Size {
			return nil, fmt.Errorf("%q is not a SHA-256 hash in hex (64 characters)", shorten(part))
		}
		var h [sha256.Size]byte
		copy(h[:], raw)
		k.hashes = append(k.hashes, h)
	}
	if len(k.hashes) == 0 {
		return nil, errors.New("no key hash given (create a key and its hash with: vwsync-api generate-key)")
	}
	return &k, nil
}

// Verify meldet, ob der vorgelegte Schlüssel zu einem der akzeptierten passt. Der Vergleich läuft
// gegen jeden Hash in konstanter Zeit. Die Dauer verrät also nicht, welcher Hash beinahe gepasst hätte.
func (k *Keys) Verify(presented string) bool {
	sum := sha256.Sum256([]byte(presented))
	match := 0
	for _, h := range k.hashes {
		match |= subtle.ConstantTimeCompare(sum[:], h[:])
	}
	return match == 1
}

// shorten hält Fehlermeldungen kurz und wiederholt nie einen langen Wert, der ein Secret sein könnte.
func shorten(s string) string {
	if len(s) > 12 {
		return s[:12] + "..."
	}
	return s
}
