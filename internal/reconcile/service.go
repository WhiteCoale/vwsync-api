package reconcile

import (
	"context"
	"fmt"
	"strings"

	"vwsync-api/internal/model"
)

// Directory is the part of the Vaultwarden client the service needs. Tests replace it with a fake.
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

// OrgKeys decrypts organization keys. Satisfied by *crypto.KeyVault.
type OrgKeys interface {
	OrganizationKey(encryptedOrgKey string) ([]byte, error)
}

// OrgNotFoundError means a desired org does not exist, or the API account is not owner/admin there.
type OrgNotFoundError struct{ Key string }

func (e *OrgNotFoundError) Error() string {
	return fmt.Sprintf("organization %q not found, or the API account is neither owner nor admin there", e.Key)
}

// OrgExistsError means an organization with that name is already managed by the API account.
type OrgExistsError struct{ Name string }

func (e *OrgExistsError) Error() string {
	return fmt.Sprintf("organization %q already exists", e.Name)
}

type Service struct{ dir Directory }

func NewService(dir Directory) *Service { return &Service{dir: dir} }

// ChangeResult is the outcome of one executed change.
type ChangeResult struct {
	Change
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// Plan reads the actual state and plans every organization of the desired state. It writes nothing.
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

// Apply executes one org plan. A failed change does not stop the rest: partial success beats aborting
// mid-run, and running again picks up what is left because planning is idempotent.
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

// PendingConfirm lists the members of one org waiting for confirmation (status "accepted").
// only is an allowlist of lower-case e-mails; nil means everyone.
func (s *Service) PendingConfirm(ctx context.Context, org model.Organization, only map[string]bool) ([]model.Member, error) {
	members, err := s.dir.OrgUsers(ctx, org.ID)
	if err != nil {
		return nil, err
	}
	var pending []model.Member
	for _, m := range members {
		if m.Status == model.Accepted && (only == nil || only[m.Email]) {
			pending = append(pending, m)
		}
	}
	return pending, nil
}

// ConfirmResult is the outcome for one member.
type ConfirmResult struct {
	Email string `json:"email"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// OrgConfirm is the confirm outcome for one org. Results is empty on a dry run.
type OrgConfirm struct {
	Org     model.Organization `json:"org"`
	Pending []string           `json:"pending"`
	Results []ConfirmResult    `json:"results,omitempty"`
}

// ConfirmAll confirms accepted members in every admin org. keys is called at most once, and only when
// something is really confirmed. On a dry run it is never called and no master password is needed.
func (s *Service) ConfirmAll(ctx context.Context, only map[string]bool, apply bool, keys func(context.Context) (OrgKeys, error)) ([]OrgConfirm, error) {
	orgs, err := s.dir.AdminOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	out := []OrgConfirm{}
	var vault OrgKeys
	for _, org := range orgs {
		pending, err := s.PendingConfirm(ctx, org, only)
		if err != nil {
			return nil, err
		}
		if len(pending) == 0 {
			continue
		}
		oc := OrgConfirm{Org: org, Pending: make([]string, len(pending))}
		for i, m := range pending {
			oc.Pending[i] = m.Email
		}
		if apply {
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

// CreateOrg creates an organization. Vaultwarden does not enforce unique names, so a second call would
// silently create a duplicate; the name is checked first, case-insensitively, among the orgs the API
// account administers. Orgs the account cannot see are not visible to this check.
// With apply=false nothing is created and the returned org has no ID.
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
