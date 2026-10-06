// Package model enthält die Werttypen, die der Vaultwarden-Client und die Abgleichslogik gemeinsam nutzen.
package model

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Role ist die Rolle eines Mitglieds in einer Organisation. Die Zahlen sind die "type"-Werte der API.
type Role int

const (
	Owner   Role = 0
	Admin   Role = 1
	User    Role = 2
	Manager Role = 3
	// Custom ist die benutzerdefinierte Rolle mit "Alle Sammlungen verwalten". Sie darf beliebige
	// Sammlungen anlegen, bearbeiten und löschen. Andere benutzerdefinierte Rollen kennt Vaultwarden nicht.
	Custom Role = 4
	// Unknown steht für jeden Typ, den der Dienst nicht kennt. Er lässt sich nicht als Soll-Rolle setzen.
	Unknown Role = 99
)

// ParseRole liest einen Rollennamen aus einem Soll-Zustand.
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

// RoleFromAPI bildet den "type" der API und die Sammlungs-Berechtigungen eines Mitglieds auf eine Rolle ab.
//
// Vaultwarden speichert einen Manager als Typ 3, meldet ihn aber als Typ 4 ("Custom"), weil aktuelle
// Bitwarden-Clients den Manager-Typ nicht mehr kennen. Typ 3 und 4 bedeuten daher dasselbe. Die drei
// Sammlungs-Berechtigungen unterscheiden die beiden Rollen.
//
//	manager: keine Sammlungs-Berechtigungen
//	custom:  beliebige Sammlungen anlegen, bearbeiten und löschen ("Alle Sammlungen verwalten")
//
// Ohne diese Zuordnung sähe jeder Manager wie eine Rollenabweichung aus und würde bei jedem Sync
// erneut "geändert".
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

// Status ist der Lebenszyklus einer Mitgliedschaft.
// Invited (noch nicht registriert) -> Accepted (registriert) -> Confirmed (vom Dienst bestätigt).
type Status int

const (
	Revoked   Status = -1
	Invited   Status = 0
	Accepted  Status = 1
	Confirmed Status = 2
)

// StatusFromAPI bildet den API-Wert ab. Unbekannte Werte werden zu Invited, damit nie versehentlich
// jemand bestätigt wird.
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

// Member ist eine Momentaufnahme einer Mitgliedschaft. Email ist immer klein geschrieben.
type Member struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Role   Role   `json:"role"`
	Status Status `json:"status"`
	// UserID ist die Konto-ID, nötig zum Abruf des öffentlichen Schlüssels. Nicht die Mitgliedschafts-ID.
	UserID string `json:"-"`
}

// Organization ist eine Organisation, die das API-Konto verwalten darf.
type Organization struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// EncryptedKey ist der Organisations-Schlüssel, verschlüsselt für das API-Konto. Nur confirm braucht ihn.
	EncryptedKey string `json:"-"`
}

// Profile ist das Ergebnis eines Aufrufs von /accounts/profile. Es enthält die Adresse des API-Kontos
// und die Organisationen, die es verwalten darf.
type Profile struct {
	Email string // klein geschrieben
	Orgs  []Organization
}
