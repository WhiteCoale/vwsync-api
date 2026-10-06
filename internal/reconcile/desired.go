// Package reconcile berechnet den Unterschied zwischen Soll- und Ist-Mitgliedschaft und setzt ihn um.
package reconcile

import (
	"fmt"
	"net/mail"
	"sort"
	"strings"

	"vwsync-api/internal/model"
)

// DesiredInput ist der JSON-Body eines Sync-Requests.
//
//	{"orgs": {"Team Alpha": {"members": {"alice@example.com": "admin"}}}}
//
// Der Schlüssel einer Org ist ihr Name oder ihre ID.
type DesiredInput struct {
	Orgs map[string]struct {
		Members map[string]model.Role `json:"members"`
	} `json:"orgs"`
}

// Desired ordnet Org-Schlüssel -> E-Mail in Kleinbuchstaben -> Rolle zu. Nach Parse ist jede E-Mail
// gültig und eindeutig.
type Desired map[string]map[string]model.Role

// Parse prüft die Eingabe vollständig, damit ein fehlerhafter Request vor dem ersten API-Aufruf
// scheitert. Eine Org mit leerer Mitgliederliste bleibt erhalten, sie bedeutet "alle entfernen".
func (in DesiredInput) Parse() (Desired, error) {
	out := Desired{}
	for orgKey, body := range in.Orgs {
		members := map[string]model.Role{}
		for raw, role := range body.Members {
			email := strings.ToLower(strings.TrimSpace(raw))
			if addr, err := mail.ParseAddress(email); err != nil || addr.Address != email {
				return nil, fmt.Errorf("%s: invalid e-mail address %q", orgKey, raw)
			}
			if _, dup := members[email]; dup {
				return nil, fmt.Errorf("%s: %s appears twice (e-mail addresses are case-insensitive)", orgKey, email)
			}
			members[email] = role
		}
		out[orgKey] = members
	}
	return out, nil
}

// OrgKeys liefert die Org-Schlüssel in stabiler Reihenfolge.
func (d Desired) OrgKeys() []string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
