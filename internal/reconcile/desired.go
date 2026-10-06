// Package reconcile computes and applies the difference between a desired and the actual membership.
package reconcile

import (
	"fmt"
	"net/mail"
	"sort"
	"strings"

	"vwsync-api/internal/model"
)

// DesiredInput is the JSON body of a sync request:
//
//	{"orgs": {"Team Alpha": {"members": {"alice@example.com": "admin"}}}}
//
// The org key is a name or an id.
type DesiredInput struct {
	Orgs map[string]struct {
		Members map[string]model.Role `json:"members"`
	} `json:"orgs"`
}

// Desired maps org key -> lower-case e-mail -> role. After Parse, every e-mail is valid and unique.
type Desired map[string]map[string]model.Role

// Parse validates the input completely, so a bad request fails before the first API call.
// An org with an empty member list is kept: it means "remove everyone".
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

// OrgKeys returns the org keys in a stable order.
func (d Desired) OrgKeys() []string {
	keys := make([]string, 0, len(d))
	for k := range d {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
