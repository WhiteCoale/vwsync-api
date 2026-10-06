package server

import (
	"bytes"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOnlyTheConfiguredKeyIsAccepted(t *testing.T) {
	e := newEnv(t, newDir())
	if rec := e.do("GET", "/v1/orgs", testKey, ""); rec.Code != 200 {
		t.Fatalf("the right key: %d %s", rec.Code, rec.Body)
	}
	for name, key := range map[string]string{
		"wrong key":        "vwsk_" + strings.Repeat("A", 43),
		"key plus suffix":  testKey + "x",
		"key minus a char": testKey[:len(testKey)-1],
		"different case":   strings.ToUpper(testKey),
		"empty":            "",
	} {
		if rec := e.do("GET", "/v1/orgs", key, ""); rec.Code != 401 {
			t.Errorf("%s: %d", name, rec.Code)
		}
	}
}

func rawRequest(e env, authorization string) int {
	req := httptest.NewRequest("GET", "/v1/orgs", nil)
	req.RemoteAddr = "127.0.0.1:50000"
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec.Code
}

func TestOnlyTheBearerSchemeCarriesTheKey(t *testing.T) {
	e := newEnv(t, newDir())
	for header, want := range map[string]int{
		"Bearer " + testKey:  200,
		"bearer " + testKey:  200, // das Schema ist unabhängig von Groß- und Kleinschreibung
		"Bearer  " + testKey: 200, // ein doppeltes Leerzeichen wird toleriert
		"Basic " + testKey:   401,
		"Token " + testKey:   401,
		testKey:              401, // der Schlüssel ohne Schema
		"Bearer":             401,
		"":                   401,
	} {
		if got := rawRequest(e, header); got != want {
			t.Errorf("%q: got %d, want %d", header, got, want)
		}
	}
}

func TestTheKeyInTheURLIsNotAccepted(t *testing.T) {
	// Ein Schlüssel in der Query würde in Access-Logs und Proxy-Logs landen.
	e := newEnv(t, newDir())
	for _, path := range []string{"/v1/orgs?key=" + testKey, "/v1/orgs?token=" + testKey, "/v1/orgs?api_key=" + testKey} {
		req := httptest.NewRequest("GET", path, nil)
		req.RemoteAddr = "127.0.0.1:50000"
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != 401 {
			t.Errorf("%s: %d", path, rec.Code)
		}
	}
}

func TestThereIsNoLoginEndpoint(t *testing.T) {
	e := newEnv(t, newDir())
	if rec := e.do("POST", "/v1/auth/login", "", `{"username":"a","password":"b"}`); rec.Code != 404 && rec.Code != 405 {
		t.Fatalf("%d", rec.Code)
	}
}

func TestRejectedRequestsAreLoggedWithTheirAddressButNeverWithTheKey(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvLog(t, newDir(), &logs)
	wrong := "vwsk_" + strings.Repeat("Z", 43)

	// Von nginx auf diesem Host, mit der echten Adresse des Aufrufers.
	e.do("GET", "/v1/orgs", wrong, "")
	// Von woanders, mit einer Adresse in X-Real-IP, der nicht geglaubt werden darf.
	req := httptest.NewRequest("GET", "/v1/orgs", nil)
	req.RemoteAddr = "203.0.113.9:4000"
	req.Header.Set("X-Real-IP", "10.9.9.9")
	req.Header.Set("Authorization", "Bearer "+wrong)
	e.h.ServeHTTP(httptest.NewRecorder(), req)

	out := logs.String()
	if !strings.Contains(out, "ip=10.0.0.1") {
		t.Errorf("the address behind the proxy is not logged:\n%s", out)
	}
	if !strings.Contains(out, "ip=203.0.113.9") || strings.Contains(out, "10.9.9.9") {
		t.Errorf("a forged X-Real-IP was believed:\n%s", out)
	}
	if strings.Count(out, "request rejected") != 2 {
		t.Errorf("expected two rejection lines:\n%s", out)
	}
	for _, secret := range []string{wrong, testKey, "Bearer"} {
		if strings.Contains(out, secret) {
			t.Fatalf("%q leaked into the log:\n%s", secret, out)
		}
	}
}

func TestAcceptedRequestsDoNotLogARejection(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvLog(t, newDir(), &logs)
	e.do("GET", "/v1/orgs", testKey, "")
	if strings.Contains(logs.String(), "request rejected") {
		t.Fatal(logs.String())
	}
}

func TestTheAccessLogNeverRepeatsUnknownQueryValues(t *testing.T) {
	var logs bytes.Buffer
	e := newEnvLog(t, newDir(), &logs)
	e.do("GET", "/v1/orgs?key="+testKey+"&token=secret-value", "", "")
	e.do("POST", "/v1/sync?dry_run=true&no_remove=true&max_removals=3&debug=x", testKey, `{"orgs":{}}`)
	out := logs.String()
	for _, leaked := range []string{testKey, "secret-value", "debug="} {
		if strings.Contains(out, leaked) {
			t.Fatalf("%q from the query reached the log:\n%s", leaked, out)
		}
	}
	if !strings.Contains(out, `query="dry_run=true&max_removals=3&no_remove=true"`) {
		t.Fatalf("the known flags must still be logged:\n%s", out)
	}
}
