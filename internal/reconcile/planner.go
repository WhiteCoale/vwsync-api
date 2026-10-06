package reconcile

import (
	"fmt"
	"sort"

	"vwsync-api/internal/model"
)

type ChangeType string

const (
	Invite     ChangeType = "invite" // in the desired state, not in the org
	ChangeRole ChangeType = "role"   // member with a different role than desired
	Remove     ChangeType = "remove" // member not in the desired state
)

// Change is one planned modification. It describes, it does not execute.
type Change struct {
	Type  ChangeType  `json:"type"`
	Email string      `json:"email"`
	Role  *model.Role `json:"role,omitempty"` // target role (invite, role)
	From  *model.Role `json:"from,omitempty"` // current role (role)

	member model.Member // existing membership (role, remove)
}

// OrgPlan is the result of planning one organization.
type OrgPlan struct {
	Org      model.Organization `json:"org"`
	Changes  []Change           `json:"changes"`
	Warnings []string           `json:"warnings"`
}

// Removals counts planned removals. It is the basis of the removal limit.
func (p OrgPlan) Removals() int {
	n := 0
	for _, c := range p.Changes {
		if c.Type == Remove {
			n++
		}
	}
	return n
}

// Plan diffs desired against current. It is a pure function. Planning is idempotent: once a plan has
// been applied, planning again yields no changes. The own account is never touched, so an operator
// cannot lock themselves out. The order of changes is stable (sorted by e-mail).
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
			// Revoked is a deliberate admin decision; it is not lifted automatically.
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
				// A revoked member is a deliberate admin decision, and /v1/export leaves revoked members
				// out of "desired". Removing them would delete what an admin only suspended.
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
