package server

import (
	"encoding/json"
	"testing"

	"vwsync-api/internal/model"
)

// waitingDir hat je ein Mitglied pro Status. Ohne Mailversand bedeutet "invited", dass die Person
// sich noch nicht registriert hat.
func waitingDir() *fakeDir {
	d := newDir()
	d.members["o1"] = []model.Member{
		{ID: "m1", Email: "done@x.io", Role: model.User, Status: model.Confirmed},
		{ID: "m2", Email: "ready@x.io", Role: model.User, Status: model.Accepted, UserID: "u2"},
		{ID: "m3", Email: "late@x.io", Role: model.User, Status: model.Invited},
		{ID: "m4", Email: "other@x.io", Role: model.User, Status: model.Invited},
	}
	return d
}

type confirmOrg struct {
	Pending []string `json:"pending"`
	Waiting []string `json:"waiting"`
	Results []struct {
		Email string
		OK    bool
	} `json:"results"`
}

func confirmResponse(t *testing.T, body []byte) []confirmOrg {
	t.Helper()
	var out struct {
		Orgs []confirmOrg `json:"orgs"`
	}
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	return out.Orgs
}

func TestConfirmSeparatesReadyFromNotYetRegistered(t *testing.T) {
	e := newEnv(t, waitingDir())
	tok := e.token(t)

	rec := e.do("POST", "/v1/confirm?dry_run=true", tok, `{"emails":["ready@x.io","late@x.io","done@x.io","typo@x.io"]}`)
	orgs := confirmResponse(t, rec.Body.Bytes())
	if rec.Code != 200 || len(orgs) != 1 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if got := orgs[0]; len(got.Pending) != 1 || got.Pending[0] != "ready@x.io" || len(got.Waiting) != 1 || got.Waiting[0] != "late@x.io" {
		t.Fatalf("an allowlisted address that has not registered must be reported as waiting, nothing else: %+v", got)
	}
}

func TestConfirmAllListsEveryoneWhoIsWaiting(t *testing.T) {
	e := newEnv(t, waitingDir())
	orgs := confirmResponse(t, e.do("POST", "/v1/confirm?dry_run=true&all=true", e.token(t), "").Body.Bytes())
	if len(orgs) != 1 || len(orgs[0].Waiting) != 2 {
		t.Fatalf("%+v", orgs)
	}
}

func TestApplyConfirmsOnlyTheRegisteredAndLeavesTheOthersAlone(t *testing.T) {
	e := newEnv(t, waitingDir())
	rec := e.do("POST", "/v1/confirm", e.token(t), `{"emails":["ready@x.io","late@x.io"]}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	if len(e.dir.writes) != 1 || e.dir.writes[0] != "confirm ready@x.io orgkey" {
		t.Fatalf("writes: %v", e.dir.writes)
	}
	orgs := confirmResponse(t, rec.Body.Bytes())
	if len(orgs[0].Results) != 1 || orgs[0].Waiting[0] != "late@x.io" {
		t.Fatalf("%+v", orgs[0])
	}
}

func TestWaitingMembersAloneNeedNoMasterPassword(t *testing.T) {
	d := waitingDir()
	d.noVault = true // Bestätigen würde scheitern, es gibt aber nichts zu bestätigen
	e := newEnv(t, d)
	rec := e.do("POST", "/v1/confirm", e.token(t), `{"emails":["late@x.io"]}`)
	if rec.Code != 200 || len(d.writes) != 0 {
		t.Fatalf("a call without confirmable members must not need the key: %d %s %v", rec.Code, rec.Body, d.writes)
	}
}

func TestOrgsWithNobodyToConfirmOrWaitForAreLeftOut(t *testing.T) {
	d := newDir()
	d.members["o1"] = []model.Member{{ID: "m1", Email: "done@x.io", Role: model.User, Status: model.Confirmed}}
	e := newEnv(t, d)
	rec := e.do("POST", "/v1/confirm?dry_run=true&all=true", e.token(t), "")
	if orgs := confirmResponse(t, rec.Body.Bytes()); rec.Code != 200 || len(orgs) != 0 {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
}
