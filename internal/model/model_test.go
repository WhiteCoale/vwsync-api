package model

import (
	"encoding/json"
	"testing"
)

func TestRoleFromAPI(t *testing.T) {
	cases := []struct {
		typ       int
		manageAll bool
		want      Role
	}{
		{0, false, Owner}, {1, false, Admin}, {2, false, User},
		{3, false, Manager}, {4, false, Manager}, // Vaultwarden reports a manager as type 4
		{3, true, Custom}, {4, true, Custom},
		{2, true, User}, // permissions only matter for type 3 and 4
		{7, false, Unknown},
	}
	for _, c := range cases {
		if got := RoleFromAPI(c.typ, c.manageAll); got != c.want {
			t.Errorf("type %d manageAll=%v: got %s, want %s", c.typ, c.manageAll, got, c.want)
		}
	}
}

func TestParseRole(t *testing.T) {
	for name, want := range map[string]Role{"owner": Owner, "ADMIN": Admin, " user ": User, "manager": Manager, "custom": Custom} {
		if got, err := ParseRole(name); err != nil || got != want {
			t.Errorf("%q: %v %v", name, got, err)
		}
	}
	for _, bad := range []string{"", "unknown", "god", "custom2"} {
		if _, err := ParseRole(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestRoleJSONRoundTrip(t *testing.T) {
	for _, r := range []Role{Owner, Admin, User, Manager, Custom} {
		b, _ := json.Marshal(r)
		var got Role
		if err := json.Unmarshal(b, &got); err != nil || got != r {
			t.Errorf("%s: %s %v", r, b, err)
		}
	}
}
