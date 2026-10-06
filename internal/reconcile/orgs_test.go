package reconcile

import (
	"context"
	"errors"
	"testing"

	"vwsync-api/internal/model"
)

func TestFindOrg(t *testing.T) {
	orgs := []model.Organization{
		{ID: "id-1", Name: "Team Alpha"},
		{ID: "id-2", Name: "Beta"},
		{ID: "id-3", Name: "twin"},
		{ID: "id-4", Name: "TWIN"},
	}
	found := map[string]string{
		"id-2":       "id-2",
		"Beta":       "id-2",
		"beta":       "id-2",
		"team alpha": "id-1",
		"TEAM ALPHA": "id-1",
		"twin":       "id-3", // two orgs match without regard to case, the exact spelling wins
		"TWIN":       "id-4",
	}
	for key, want := range found {
		if got, err := FindOrg(orgs, key); err != nil || got.ID != want {
			t.Errorf("%q: %+v %v", key, got, err)
		}
	}

	var amb *OrgAmbiguousError
	if _, err := FindOrg(orgs, "Twin"); !errors.As(err, &amb) || len(amb.IDs) != 2 {
		t.Errorf("Twin should be ambiguous: %v", err)
	}
	var nf *OrgNotFoundError
	for _, key := range []string{"nope", "", "ID-2"} {
		if _, err := FindOrg(orgs, key); !errors.As(err, &nf) {
			t.Errorf("%q: %v", key, err)
		}
	}
}

func TestPlanLeavesRevokedMembersAloneWhenTheyAreNotDesired(t *testing.T) {
	current := []model.Member{
		member("paused@x.io", model.User, model.Revoked),
		member("gone@x.io", model.User, model.Confirmed),
	}
	p := Plan(org, map[string]model.Role{}, current, "me@x.io", true)
	if got := summary(p); len(got) != 1 || got[0] != "remove:gone@x.io" {
		t.Fatalf("changes: %v", got)
	}
	if len(p.Warnings) != 1 || p.Warnings[0] == "" {
		t.Fatalf("the skipped revoked member must be reported: %v", p.Warnings)
	}
}

// profileDir counts how often the profile is fetched.
type profileDir struct {
	Directory
	profiles int
	orgCalls int
	users    map[string][]model.Member
}

func (d *profileDir) Profile(context.Context) (model.Profile, error) {
	d.profiles++
	return model.Profile{Email: "me@x.io", Orgs: []model.Organization{{ID: "o1", Name: "Team"}}}, nil
}
func (d *profileDir) AdminOrganizations(context.Context) ([]model.Organization, error) {
	d.orgCalls++
	return nil, nil
}
func (d *profileDir) SelfEmail(context.Context) (string, error) {
	d.orgCalls++
	return "", nil
}
func (d *profileDir) OrgUsers(_ context.Context, id string) ([]model.Member, error) {
	return d.users[id], nil
}

func TestPlanFetchesTheProfileOnce(t *testing.T) {
	d := &profileDir{users: map[string][]model.Member{"o1": nil}}
	desired := Desired{"Team": {"a@x.io": model.User}, "team": {"b@x.io": model.User}, "o1": {}}
	if _, err := NewService(d).Plan(context.Background(), desired, true); err != nil {
		t.Fatal(err)
	}
	if d.profiles != 1 || d.orgCalls != 0 {
		t.Fatalf("profile fetched %d times, %d extra calls", d.profiles, d.orgCalls)
	}
}
