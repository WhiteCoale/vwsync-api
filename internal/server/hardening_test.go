package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"vwsync-api/internal/model"
)

func TestLimiterKey(t *testing.T) {
	cases := map[string]string{
		"203.0.113.7":                "203.0.113.7",
		"::ffff:203.0.113.7":         "203.0.113.7",
		"2001:db8:1:2:aaaa:bbbb:1:2": "2001:db8:1:2::/64",
		"2001:db8:1:2:ffff::9":       "2001:db8:1:2::/64", // same /64 as the line above
		"not-an-ip":                  "not-an-ip",
	}
	for in, want := range cases {
		if got := limiterKey(in); got != want {
			t.Errorf("%s: got %s, want %s", in, got, want)
		}
	}
}

// loginFrom sends one wrong login from the given remote address, with an optional X-Real-IP header.
func loginFrom(e env, remote, realIP string) int {
	req := httptest.NewRequest("POST", "/v1/auth/login", strings.NewReader(`{"username":"svc","password":"wrong-password"}`))
	req.RemoteAddr = remote
	if realIP != "" {
		req.Header.Set("X-Real-IP", realIP)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code
}

func TestXRealIPIsIgnoredUnlessTheRequestComesFromLoopback(t *testing.T) {
	e := newEnv(t, newDir())
	// An attacker who reaches the port directly invents a new address on every attempt.
	for i := 0; i < loginFailuresPerMin; i++ {
		if code := loginFrom(e, "203.0.113.50:4000", "10.9.9."+string(rune('1'+i))); code != 401 {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	if code := loginFrom(e, "203.0.113.50:4001", "10.9.9.200"); code != 429 {
		t.Fatalf("a forged X-Real-IP dodged the limit: %d", code)
	}
}

func TestXRealIPIsUsedFromLoopback(t *testing.T) {
	e := newEnv(t, newDir())
	for i := 0; i < loginFailuresPerMin; i++ {
		loginFrom(e, "127.0.0.1:4000", "198.51.100.1")
	}
	if code := loginFrom(e, "127.0.0.1:4001", "198.51.100.1"); code != 429 {
		t.Fatalf("same real client must be blocked: %d", code)
	}
	if code := loginFrom(e, "127.0.0.1:4002", "198.51.100.2"); code != 401 {
		t.Fatalf("a different real client must not be blocked: %d", code)
	}
}

func TestIPv6ClientsShareTheirSlash64(t *testing.T) {
	e := newEnv(t, newDir())
	for i := 0; i < loginFailuresPerMin; i++ {
		loginFrom(e, "127.0.0.1:4000", "2001:db8:5:5::"+string(rune('a'+i)))
	}
	if code := loginFrom(e, "127.0.0.1:4001", "2001:db8:5:5:ffff::1"); code != 429 {
		t.Fatalf("rotating inside a /64 dodged the limit: %d", code)
	}
	if code := loginFrom(e, "127.0.0.1:4002", "2001:db8:5:6::1"); code != 401 {
		t.Fatalf("another /64 must not be blocked: %d", code)
	}
}

func chunkedRequest(method, path, token, body string) *http.Request {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.ContentLength = -1 // what Go sets for Transfer-Encoding: chunked
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = "127.0.0.1:50000"
	return req
}

func TestConfirmTreatsAnEmptyChunkedBodyAsNoBody(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)

	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, chunkedRequest("POST", "/v1/confirm", tok, ""))
	if rec.Code != 400 || strings.Contains(rec.Body.String(), "EOF") || !strings.Contains(rec.Body.String(), "emails") {
		t.Fatalf("empty chunked body must give the same answer as no body: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, chunkedRequest("POST", "/v1/confirm?all=true", tok, ""))
	if rec.Code != 200 {
		t.Fatalf("all=true with an empty chunked body: %d %s", rec.Code, rec.Body)
	}
	rec = httptest.NewRecorder()
	e.h.ServeHTTP(rec, chunkedRequest("POST", "/v1/confirm", tok, `{"emails":["wait@x.io"]}`))
	if rec.Code != 200 {
		t.Fatalf("chunked body with content: %d %s", rec.Code, rec.Body)
	}
}

func TestMalformedBodyIsStillRejectedWhereTheBodyIsOptional(t *testing.T) {
	e := newEnv(t, newDir())
	if rec := e.do("POST", "/v1/confirm?all=true", e.token(t), `{"emails":`); rec.Code != 400 {
		t.Fatalf("%d", rec.Code)
	}
}

func TestPanicIsLoggedWithStackAndNotLeaked(t *testing.T) {
	var logs bytes.Buffer
	dir := newDir()
	dir.panicOn = true
	e := newEnvLog(t, dir, &logs)
	rec := e.do("GET", "/v1/orgs", e.token(t), "")
	if rec.Code != 500 || strings.Contains(rec.Body.String(), "boom") || !strings.Contains(rec.Body.String(), "ref ") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	out := logs.String()
	if !strings.Contains(out, "boom in test") || !strings.Contains(out, "goroutine") || !strings.Contains(out, "AdminOrganizations") {
		t.Fatalf("log has no stack trace:\n%s", out)
	}
}

func TestRequestLogShowsWhetherItWasADryRun(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvLog(t, newDir(), &logs)
	tok := e.token(t)
	body := `{"orgs":{"Team":{"members":{"keep@x.io":"user"}}}}`
	e.do("POST", "/v1/sync?no_remove=true", tok, body)
	e.do("POST", "/v1/sync?apply=true&no_remove=true", tok, body)
	out := logs.String()
	if !strings.Contains(out, `query="no_remove=true"`) || !strings.Contains(out, `query="apply=true&no_remove=true"`) {
		t.Fatalf("access log does not show the query:\n%s", out)
	}
	if strings.Contains(out, tok) || strings.Contains(out, "Bearer") {
		t.Fatal("token in the log")
	}
}

func TestEveryAppliedChangeIsAudited(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvLog(t, newDir(), &logs)
	tok := e.token(t)
	body := `{"orgs":{"Team":{"members":{"keep@x.io":"admin","new@x.io":"user","wait@x.io":"user","other@x.io":"user"}}}}`

	e.do("POST", "/v1/sync", tok, body) // dry run: nothing to audit
	if strings.Contains(logs.String(), "msg=audit") {
		t.Fatalf("a dry run was audited as if it had changed something:\n%s", logs.String())
	}
	e.do("POST", "/v1/sync?apply=true", tok, body)
	e.do("POST", "/v1/confirm?apply=true", tok, `{"emails":["wait@x.io"]}`)

	var audit []string
	for _, l := range strings.Split(logs.String(), "\n") {
		if strings.Contains(l, "msg=audit") {
			audit = append(audit, l)
		}
	}
	joined := strings.Join(audit, "\n")
	for _, want := range []string{
		`type=invite email=new@x.io ok=true role=user`,
		`type=role email=keep@x.io ok=true role=admin from=user`,
		`type=remove email=gone@x.io ok=true`,
		`type=confirm email=wait@x.io ok=true`,
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit lacks %q:\n%s", want, joined)
		}
	}
	if len(audit) != 4 {
		t.Errorf("expected 4 audit lines, got %d:\n%s", len(audit), joined)
	}
}

func TestOrgsAreFoundWithoutRegardToLetterCase(t *testing.T) {
	e := newEnv(t, newDir())
	tok := e.token(t)
	for _, key := range []string{"team", "TEAM", "Team", "o1"} {
		if rec := e.do("GET", "/v1/orgs/"+key+"/members", tok, ""); rec.Code != 200 {
			t.Errorf("members of %q: %d %s", key, rec.Code, rec.Body)
		}
		rec := e.do("POST", "/v1/sync", tok, `{"orgs":{"`+key+`":{"members":{"keep@x.io":"user"}}}}`)
		if rec.Code != 200 {
			t.Errorf("sync of %q: %d %s", key, rec.Code, rec.Body)
		}
	}
	if rec := e.do("GET", "/v1/orgs/O1/members", tok, ""); rec.Code != 404 {
		t.Errorf("ids are exact, O1 is not o1: %d", rec.Code)
	}
}

func TestAmbiguousOrgNamesNeedTheIDOrTheExactSpelling(t *testing.T) {
	dir := newDir()
	dir.orgs = []model.Organization{{ID: "id-lower", Name: "team"}, {ID: "id-upper", Name: "TEAM"}}
	dir.members = map[string][]model.Member{"id-lower": nil, "id-upper": nil}
	e := newEnv(t, dir)
	tok := e.token(t)

	if rec := e.do("GET", "/v1/orgs/Team/members", tok, ""); rec.Code != 422 || !strings.Contains(rec.Body.String(), "use the id") {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	for key, wantID := range map[string]string{"team": "id-lower", "TEAM": "id-upper", "id-upper": "id-upper"} {
		rec := e.do("GET", "/v1/orgs/"+key+"/members", tok, "")
		var got struct{ ID string }
		_ = json.Unmarshal(rec.Body.Bytes(), &got)
		if rec.Code != 200 || got.ID != wantID {
			t.Errorf("%s: %d %s", key, rec.Code, rec.Body)
		}
	}
	if rec := e.do("POST", "/v1/sync", tok, `{"orgs":{"Team":{"members":{}}}}`); rec.Code != 422 {
		t.Fatalf("sync must not guess between two orgs: %d", rec.Code)
	}
}

func TestExportedStateNeverRemovesRevokedMembers(t *testing.T) {
	dir := newDir()
	dir.members["o1"] = append(dir.members["o1"], model.Member{ID: "m9", Email: "paused@x.io", Role: model.User, Status: model.Revoked})
	e := newEnv(t, dir)
	tok := e.token(t)

	exp := e.do("GET", "/v1/export", tok, "")
	var parsed struct {
		Desired json.RawMessage `json:"desired"`
	}
	_ = json.Unmarshal(exp.Body.Bytes(), &parsed)
	if strings.Contains(string(parsed.Desired), "paused@x.io") {
		t.Fatal("revoked members must stay out of the exported desired state")
	}

	rec := e.do("POST", "/v1/sync?apply=true", tok, string(parsed.Desired))
	if rec.Code != 200 || len(dir.writes) != 0 {
		t.Fatalf("syncing the export back changed something: %d %v %s", rec.Code, dir.writes, rec.Body)
	}
	if !strings.Contains(rec.Body.String(), "paused@x.io is revoked") {
		t.Fatalf("the skipped revoked member is not reported: %s", rec.Body)
	}
}

func TestEmptyDesiredStateKeepsRevokedMembers(t *testing.T) {
	dir := newDir()
	dir.members["o1"] = []model.Member{
		{ID: "m1", Email: "gone@x.io", Role: model.User, Status: model.Confirmed},
		{ID: "m9", Email: "paused@x.io", Role: model.User, Status: model.Revoked},
	}
	e := newEnv(t, dir)
	rec := e.do("POST", "/v1/sync?apply=true", e.token(t), `{"orgs":{"Team":{"members":{}}}}`)
	if rec.Code != 200 || len(dir.writes) != 1 || dir.writes[0] != "remove m1" {
		t.Fatalf("%d %v %s", rec.Code, dir.writes, rec.Body)
	}
}
