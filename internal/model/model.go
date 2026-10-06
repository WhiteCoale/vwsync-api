// Package model holds the value types shared by the Vaultwarden client and the reconcile logic.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Role is a member's role in an organization. The numbers are the API's "type" values.
type Role int

const (
	Owner   Role = 0
	Admin   Role = 1
	User    Role = 2
	Manager Role = 3
	// Custom is the custom role with "Manage all collections": create, edit and delete any collection.
	// Vaultwarden has no other kind of custom role.
	Custom Role = 4
	// Unknown is any type this tool does not know. It cannot be assigned through a desired state.
	Unknown Role = 99
)

// ParseRole reads a role name from a desired state.
func ParseRole(name string) (Role, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "owner":
		return Owner, nil
	case "admin":
		return Admin, nil
	case "user":
		return User, nil
	case "manager":
		return Manager, nil
	case "custom":
		return Custom, nil
	}
	return 0, fmt.Errorf("unknown role %q (allowed: owner, admin, manager, custom, user)", name)
}

// RoleFromAPI maps the API's "type" and the member's collection permissions to a role.
//
// Vaultwarden stores a Manager as type 3 but reports it as type 4 ("Custom"), because current Bitwarden
// clients no longer know the Manager type. Type 3 and 4 therefore mean the same thing, and the three
// collection permissions tell the two roles apart:
//
//	manager: no collection permissions
//	custom:  create, edit and delete any collection ("Manage all collections")
//
// Without this, every manager would look like a role mismatch and be "changed" on each sync.
func RoleFromAPI(t int, manageAllCollections bool) Role {
	switch Role(t) {
	case Owner, Admin, User:
		return Role(t)
	case Manager, Custom:
		if manageAllCollections {
			return Custom
		}
		return Manager
	}
	return Unknown
}

func (r Role) String() string {
	switch r {
	case Owner:
		return "owner"
	case Admin:
		return "admin"
	case User:
		return "user"
	case Manager:
		return "manager"
	case Custom:
		return "custom"
	}
	return "unknown"
}

func (r Role) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *Role) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("role must be a string")
	}
	parsed, err := ParseRole(s)
	if err != nil {
		return err
	}
	*r = parsed
	return nil
}

// Status is the membership lifecycle:
// Invited -> Accepted (user accepts) -> Confirmed (admin confirms).
type Status int

const (
	Revoked   Status = -1
	Invited   Status = 0
	Accepted  Status = 1
	Confirmed Status = 2
)

// StatusFromAPI maps the API value. Unknown values become Invited so nothing is confirmed by accident.
func StatusFromAPI(s int) Status {
	switch Status(s) {
	case Revoked, Invited, Accepted, Confirmed:
		return Status(s)
	}
	return Invited
}

func (s Status) String() string {
	switch s {
	case Revoked:
		return "revoked"
	case Accepted:
		return "accepted"
	case Confirmed:
		return "confirmed"
	}
	return "invited"
}

func (s Status) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Member is a snapshot of one organization membership. Email is always lower case.
type Member struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Role   Role   `json:"role"`
	Status Status `json:"status"`
	// UserID is the account id, needed to fetch the public key. Not the membership id.
	UserID string `json:"-"`
}

// Organization is an organization the API account may manage.
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// EncryptedKey is the organization key, encrypted for the API account. Only confirm needs it.
	EncryptedKey string `json:"-"`
}

// Profile is what one /accounts/profile call yields: the API account's address and the organizations
// it may manage.
type Profile struct {
	Email string // lower case
	Orgs  []Organization
}
