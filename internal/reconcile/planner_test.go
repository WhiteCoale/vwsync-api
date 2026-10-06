package reconcile

import (
	"reflect"
	"strings"
	"testing"

	"vwsync-api/internal/model"
)

var org = model.Organization{ID: "o1", Name: "Team"}

func member(email string, role model.Role, status model.Status) model.Member {
	return model.Member{ID: "m-" + email, Email: email, Role: role, Status: status}
}

func summary(p OrgPlan) []string {
	var s []string
	for _, c := range p.Changes {
		s = append(s, string(c.Type)+":"+c.Email)
	}
	return s
}

func TestPlanInviteRoleRemoveInStableOrder(t *testing.T) {
	desired := map[string]model.Role{"zed@x.io": model.User, "amy@x.io": model.Admin, "bob@x.io": model.Admin}
	current := []model.Member{
		member("bob@x.io", model.User, model.Confirmed),
		member("old@x.io", model.User, model.Confirmed),
		member("cat@x.io", model.User, model.Invited),
	}
	got := summary(Plan(org, desired, current, "me@x.io", true))
	want := []string{"invite:amy@x.io", "role:bob@x.io", "invite:zed@x.io", "remove:cat@x.io", "remove:old@x.io"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestPlanNeverTouchesSelf(t *testing.T) {
	current := []model.Member{member("me@x.io", model.Owner, model.Confirmed)}
	if got := Plan(org, map[string]model.Role{}, current, "me@x.io", true); len(got.Changes) != 0 {
		t.Fatalf("removed self: %v", summary(got))
	}
	if got := Plan(org, map[string]model.Role{"me@x.io": model.User}, current, "me@x.io", true); len(got.Changes) != 0 {
		t.Fatalf("changed own role: %v", summary(got))
	}
}

func TestPlanSkipsRevokedWithWarning(t *testing.T) {
	current := []model.Member{member("r@x.io", model.User, model.Revoked)}
	p := Plan(org, map[string]model.Role{"r@x.io": model.Admin}, current, "me@x.io", true)
	if len(p.Changes) != 0 || len(p.Warnings) != 1 || !strings.Contains(p.Warnings[0], "r@x.io") {
		t.Fatalf("%+v", p)
	}
}

func TestPlanNoRemoval(t *testing.T) {
	current := []model.Member{member("old@x.io", model.User, model.Confirmed)}
	if p := Plan(org, map[string]model.Role{}, current, "me@x.io", false); len(p.Changes) != 0 {
		t.Fatalf("removed although removal is off: %v", summary(p))
	}
}

func TestPlanIsIdempotent(t *testing.T) {
	desired := map[string]model.Role{"a@x.io": model.Admin, "b@x.io": model.User}
	var current []model.Member
	for e, r := range desired {
		current = append(current, member(e, r, model.Confirmed))
	}
	if p := Plan(org, desired, current, "me@x.io", true); len(p.Changes) != 0 {
		t.Fatalf("not idempotent: %v", summary(p))
	}
}

func TestPlanHasNoNilSlices(t *testing.T) {
	p := Plan(org, map[string]model.Role{}, nil, "me@x.io", true)
	if p.Changes == nil || p.Warnings == nil {
		t.Fatal("nil slices marshal to null")
	}
}

type members = map[string]model.Role

func input(org string, m members) DesiredInput {
	in := DesiredInput{Orgs: map[string]struct {
		Members map[string]model.Role `json:"members"`
	}{}}
	in.Orgs[org] = struct {
		Members map[string]model.Role `json:"members"`
	}{Members: m}
	return in
}

func TestParseDesired(t *testing.T) {
	d, err := input("Team", members{" Alice@X.io ": model.Admin}).Parse()
	if err != nil || d["Team"]["alice@x.io"] != model.Admin {
		t.Fatal(d, err)
	}
	if _, err := input("Team", members{"not-an-email": model.User}).Parse(); err == nil {
		t.Fatal("invalid e-mail accepted")
	}
	if _, err := input("Team", members{"a@x.io": model.User, "A@x.io": model.Admin}).Parse(); err == nil {
		t.Fatal("case-insensitive duplicate accepted")
	}
	if d, err := input("Empty", members{}).Parse(); err != nil || d["Empty"] == nil {
		t.Fatal("an org with no members must be kept: it means remove everyone")
	}
}
