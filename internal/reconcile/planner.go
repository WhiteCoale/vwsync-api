package reconcile

import (
	"fmt"
	"sort"

	"vwsync-api/internal/model"
)

type ChangeType string

const (
	Invite     ChangeType = "invite" // im Soll, aber nicht in der Org
	ChangeRole ChangeType = "role"   // Mitglied mit anderer Rolle als im Soll
	Remove     ChangeType = "remove" // Mitglied, das nicht im Soll steht
)

// Change ist eine geplante Änderung. Sie beschreibt nur und führt nichts aus.
type Change struct {
	Type  ChangeType  `json:"type"`
	Email string      `json:"email"`
	Role  *model.Role `json:"role,omitempty"` // Zielrolle (invite, role)
	From  *model.Role `json:"from,omitempty"` // bisherige Rolle (role)

	member model.Member // bestehende Mitgliedschaft (role, remove)
}

// OrgPlan ist das Ergebnis der Planung für eine Organisation.
type OrgPlan struct {
	Org      model.Organization `json:"org"`
	Changes  []Change           `json:"changes"`
	Warnings []string           `json:"warnings"`
}

// Removals zählt die geplanten Entfernungen. Darauf beruht die Obergrenze max_removals.
func (p OrgPlan) Removals() int {
	n := 0
	for _, c := range p.Changes {
		if c.Type == Remove {
			n++
		}
	}
	return n
}

// Plan vergleicht Soll und Ist. Die Funktion ist rein und ohne Seiteneffekte. Die Planung ist
// idempotent. Nach der Ausführung eines Plans ergibt eine erneute Planung keine Änderungen. Das
// eigene Konto bleibt immer unberührt, damit sich der Betreiber nicht aussperrt. Die Reihenfolge der
// Änderungen ist stabil, sortiert nach E-Mail.
func Plan(org model.Organization, desired map[string]model.Role, current []model.Member, selfEmail string, allowRemoval bool) OrgPlan {
	byEmail := make(map[string]model.Member, len(current))
	for _, m := range current {
		byEmail[m.Email] = m
	}
	plan := OrgPlan{Org: org, Changes: []Change{}, Warnings: []string{}}

	for _, email := range sortedKeys(desired) {
		role := desired[email]
		if email == selfEmail {
			continue
		}
		m, exists := byEmail[email]
		switch {
		case !exists:
			plan.Changes = append(plan.Changes, Change{Type: Invite, Email: email, Role: &role})
		case m.Status == model.Revoked:
			// Eine Sperre ist die bewusste Entscheidung eines Admins und wird nicht automatisch aufgehoben.
			plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s is revoked in %q and was skipped", email, org.Name))
		case m.Role != role:
			from := m.Role
			plan.Changes = append(plan.Changes, Change{Type: ChangeRole, Email: email, Role: &role, From: &from, member: m})
		}
	}

	if allowRemoval {
		for _, email := range sortedKeys(byEmail) {
			if _, wanted := desired[email]; wanted || email == selfEmail {
				continue
			}
			if byEmail[email].Status == model.Revoked {
				// Eine Sperre ist die bewusste Entscheidung eines Admins, und /v1/export lässt gesperrte
				// Mitglieder in "desired" weg. Sie zu entfernen, würde löschen, was ein Admin nur ausgesetzt hat.
				plan.Warnings = append(plan.Warnings, fmt.Sprintf("%s is revoked in %q and was left alone", email, org.Name))
				continue
			}
			plan.Changes = append(plan.Changes, Change{Type: Remove, Email: email, member: byEmail[email]})
		}
	}
	return plan
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
