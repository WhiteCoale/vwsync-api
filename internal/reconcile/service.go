package reconcile

import (
	"context"
	"fmt"
	"strings"

	"vwsync-api/internal/model"
)

// Directory ist der Teil des Vaultwarden-Clients, den der Service braucht. Tests ersetzen ihn durch
// eine Attrappe.
type Directory interface {
	Profile(ctx context.Context) (model.Profile, error)
	SelfEmail(ctx context.Context) (string, error)
	AdminOrganizations(ctx context.Context) ([]model.Organization, error)
	OrgUsers(ctx context.Context, orgID string) ([]model.Member, error)
	Invite(ctx context.Context, orgID, email string, role model.Role) error
	ChangeRole(ctx context.Context, orgID, memberID string, role model.Role) error
	Remove(ctx context.Context, orgID, memberID string) error
	Confirm(ctx context.Context, orgID string, m model.Member, orgKey []byte) error
	CreateOrganization(ctx context.Context, name, billingEmail string) (model.Organization, error)
}

// OrgKeys entschlüsselt Organisations-Schlüssel. *crypto.KeyVault erfüllt das Interface.
type OrgKeys interface {
	OrganizationKey(encryptedOrgKey string) ([]byte, error)
}

// OrgNotFoundError bedeutet, dass eine gewünschte Org nicht existiert oder das API-Konto dort weder
// Owner noch Admin ist.
type OrgNotFoundError struct{ Key string }

func (e *OrgNotFoundError) Error() string {
	return fmt.Sprintf("organization %q not found, or the API account is neither owner nor admin there", e.Key)
}

// OrgExistsError bedeutet, dass das API-Konto bereits eine Organisation mit diesem Namen verwaltet.
type OrgExistsError struct{ Name string }

func (e *OrgExistsError) Error() string {
	return fmt.Sprintf("organization %q already exists", e.Name)
}

type Service struct{ dir Directory }

func NewService(dir Directory) *Service { return &Service{dir: dir} }

// ChangeResult ist das Ergebnis einer ausgeführten Änderung.
type ChangeResult struct {
	Change
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Plan liest den Ist-Zustand und plant jede Organisation aus dem Soll. Es wird nichts geschrieben.
func (s *Service) Plan(ctx context.Context, desired Desired, allowRemoval bool) ([]OrgPlan, error) {
	profile, err := s.dir.Profile(ctx)
	if err != nil {
		return nil, err
	}

	plans := make([]OrgPlan, 0, len(desired))
	for _, key := range desired.OrgKeys() {
		org, err := FindOrg(profile.Orgs, key)
		if err != nil {
			return nil, err
		}
		current, err := s.dir.OrgUsers(ctx, org.ID)
		if err != nil {
			return nil, err
		}
		plans = append(plans, Plan(org, desired[key], current, profile.Email, allowRemoval))
	}
	return plans, nil
}

// Apply führt den Plan einer Org aus. Eine fehlgeschlagene Änderung stoppt die übrigen nicht. Ein
// Teilerfolg ist besser als ein Abbruch mitten im Lauf, und ein erneuter Lauf holt den Rest nach,
// weil die Planung idempotent ist.
func (s *Service) Apply(ctx context.Context, plan OrgPlan) []ChangeResult {
	results := make([]ChangeResult, 0, len(plan.Changes))
	for _, c := range plan.Changes {
		r := ChangeResult{Change: c, OK: true}
		if err := s.execute(ctx, plan.Org.ID, c); err != nil {
			r.OK, r.Error = false, err.Error()
		}
		results = append(results, r)
	}
	return results
}

func (s *Service) execute(ctx context.Context, orgID string, c Change) error {
	switch c.Type {
	case Invite:
		return s.dir.Invite(ctx, orgID, c.Email, *c.Role)
	case ChangeRole:
		return s.dir.ChangeRole(ctx, orgID, c.member.ID, *c.Role)
	case Remove:
		return s.dir.Remove(ctx, orgID, c.member.ID)
	}
	return fmt.Errorf("unknown change type %q", c.Type)
}

// Candidates teilt die Mitglieder einer Org, die zur Auswahl passen (nil bedeutet alle), in solche, die
// sich jetzt bestätigen lassen, und solche, bei denen das noch nicht geht.
//
// Pending sind Mitglieder mit Status "accepted". Sie haben sich registriert und besitzen deshalb ein
// Schlüsselpaar. Waiting sind Mitglieder mit Status "invited". Ohne Mailversand sind das eingeladene
// Personen, die sich noch nicht registriert haben. Für sie gibt es noch keinen öffentlichen Schlüssel,
// mit dem sich der Organisations-Schlüssel verschlüsseln ließe. Sobald sie sich registrieren, wechseln
// sie von selbst auf "accepted", und ein späterer confirm-Aufruf bestätigt sie.
func (s *Service) Candidates(ctx context.Context, org model.Organization, only map[string]bool) (pending []model.Member, waiting []string, err error) {
	members, err := s.dir.OrgUsers(ctx, org.ID)
	if err != nil {
		return nil, nil, err
	}
	for _, m := range members {
		if only != nil && !only[m.Email] {
			continue
		}
		switch m.Status {
		case model.Accepted:
			pending = append(pending, m)
		case model.Invited:
			waiting = append(waiting, m.Email)
		}
	}
	return pending, waiting, nil
}

// ConfirmResult ist das Ergebnis für ein Mitglied.
type ConfirmResult struct {
	Email string `json:"email"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// OrgConfirm ist das Ergebnis von confirm für eine Org. Results ist bei einer Vorschau leer.
type OrgConfirm struct {
	Org model.Organization `json:"org"`
	// Pending sind die Mitglieder, die sich jetzt bestätigen lassen.
	Pending []string `json:"pending"`
	// Waiting sind passende Mitglieder, die sich noch nicht registriert haben. Ein späterer Aufruf
	// bestätigt sie.
	Waiting []string        `json:"waiting"`
	Results []ConfirmResult `json:"results,omitempty"`
}

// ConfirmAll bestätigt registrierte Mitglieder in jeder verwalteten Org und meldet die, deren
// Registrierung noch aussteht. keys wird höchstens einmal aufgerufen, und nur wenn wirklich jemand
// bestätigt wird. Bei einer Vorschau wird es nie aufgerufen, und es ist kein Master-Passwort nötig.
func (s *Service) ConfirmAll(ctx context.Context, only map[string]bool, apply bool, keys func(context.Context) (OrgKeys, error)) ([]OrgConfirm, error) {
	orgs, err := s.dir.AdminOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	out := []OrgConfirm{}
	var vault OrgKeys
	for _, org := range orgs {
		pending, waiting, err := s.Candidates(ctx, org, only)
		if err != nil {
			return nil, err
		}
		if len(pending) == 0 && len(waiting) == 0 {
			continue
		}
		oc := OrgConfirm{Org: org, Pending: make([]string, len(pending)), Waiting: orEmptyStrings(waiting)}
		for i, m := range pending {
			oc.Pending[i] = m.Email
		}
		if apply && len(pending) > 0 {
			if vault == nil {
				if vault, err = keys(ctx); err != nil {
					return nil, err
				}
			}
			oc.Results = s.confirm(ctx, org, pending, vault)
		}
		out = append(out, oc)
	}
	return out, nil
}

func (s *Service) confirm(ctx context.Context, org model.Organization, members []model.Member, vault OrgKeys) []ConfirmResult {
	orgKey, err := vault.OrganizationKey(org.EncryptedKey)
	results := make([]ConfirmResult, 0, len(members))
	for _, m := range members {
		r := ConfirmResult{Email: m.Email, OK: true}
		if err == nil {
			err2 := s.dir.Confirm(ctx, org.ID, m, orgKey)
			if err2 != nil {
				r.OK, r.Error = false, err2.Error()
			}
		} else {
			r.OK, r.Error = false, "cannot decrypt organization key: "+err.Error()
		}
		results = append(results, r)
	}
	return results
}

// CreateOrg legt eine Organisation an. Vaultwarden erzwingt keine eindeutigen Namen, ein zweiter Aufruf
// würde also still ein Duplikat anlegen. Deshalb wird der Name vorher ohne Beachtung der Groß- und
// Kleinschreibung unter den Orgs geprüft, die das API-Konto verwaltet. Orgs, die das Konto nicht sieht,
// erfasst diese Prüfung nicht. Ist apply false, wird nichts angelegt, und die gelieferte Org hat keine ID.
func (s *Service) CreateOrg(ctx context.Context, name, billingEmail string, apply bool) (model.Organization, error) {
	orgs, err := s.dir.AdminOrganizations(ctx)
	if err != nil {
		return model.Organization{}, err
	}
	for _, o := range orgs {
		if strings.EqualFold(o.Name, name) {
			return model.Organization{}, &OrgExistsError{Name: o.Name}
		}
	}
	if !apply {
		return model.Organization{Name: name}, nil
	}
	if billingEmail == "" {
		if billingEmail, err = s.dir.SelfEmail(ctx); err != nil {
			return model.Organization{}, err
		}
	}
	return s.dir.CreateOrganization(ctx, name, billingEmail)
}

func orEmptyStrings(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}
