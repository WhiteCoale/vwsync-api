package vaultwarden

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// rotatingFake liefert einen Client gegen einen Testserver, der bei jedem Login ein neues Token ausgibt
// und nur das zuletzt ausgegebene akzeptiert. Die Uhr des Clients ist steuerbar.
func rotatingFake(t *testing.T) (*Client, *fakeVW, *time.Time) {
	t.Helper()
	c, f := newFake(t, good)
	f.rotating = true
	f.handlers["GET /api/accounts/profile"] = `{"email":"a@x.io"}`
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	c.now = func() time.Time { return now }
	return c, f, &now
}

func profile(t *testing.T, c *Client) error {
	t.Helper()
	_, err := c.SelfEmail(context.Background())
	return err
}

func TestTheTokenIsRenewedShortlyBeforeItExpires(t *testing.T) {
	c, f, now := rotatingFake(t) // expires_in ist 7200 Sekunden
	if err := profile(t, c); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(7200*time.Second - 61*time.Second)
	if err := profile(t, c); err != nil || f.logins.Load() != 1 {
		t.Fatalf("61 seconds before expiry the token must still be used: logins=%d err=%v", f.logins.Load(), err)
	}
	*now = now.Add(2 * time.Second) // jetzt weniger als 60 Sekunden vor Ablauf
	if err := profile(t, c); err != nil || f.logins.Load() != 2 {
		t.Fatalf("the token must be renewed before it expires: logins=%d err=%v", f.logins.Load(), err)
	}
}

func TestAVeryShortTokenLifetimeStillRenewsInTime(t *testing.T) {
	c, f, now := rotatingFake(t)
	f.login["expires_in"] = 30 // kürzer als der Sicherheitsabstand von 60 Sekunden
	if err := profile(t, c); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(61 * time.Second)
	if err := profile(t, c); err != nil || f.logins.Load() != 2 {
		t.Fatalf("logins=%d err=%v", f.logins.Load(), err)
	}
}

func TestARevokedTokenIsReplacedOnceAndTheRequestRepeated(t *testing.T) {
	c, f, _ := rotatingFake(t)
	if err := profile(t, c); err != nil {
		t.Fatal(err)
	}
	f.revoke() // etwa nach einem Wechsel des Signaturschlüssels von Vaultwarden
	if err := profile(t, c); err != nil {
		t.Fatalf("a revoked token must lead to a new login and a successful retry: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("logins: %d", f.logins.Load())
	}
}

func TestManyRequestsHittingARevokedTokenCauseOnlyOneNewLogin(t *testing.T) {
	c, f, _ := rotatingFake(t)
	if err := profile(t, c); err != nil {
		t.Fatal(err)
	}
	f.revoke()

	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.SelfEmail(context.Background()); err != nil {
				errs <- err
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Errorf("request failed: %v", err)
	}
	if got := f.logins.Load(); got != 2 {
		t.Fatalf("20 parallel requests with a revoked token logged in %d times instead of once more", got-1)
	}
}

func TestAPersistent401IsReportedAfterOneRetryWithoutLooping(t *testing.T) {
	c, f := newFake(t, good)
	f.handlers["GET /api/accounts/profile"] = `{"email":"a@x.io"}`
	f.reject.Store(1000) // Vaultwarden lehnt jedes Token ab
	_, err := c.SelfEmail(context.Background())
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusUnauthorized {
		t.Fatalf("expected the 401 to reach the caller: %v", err)
	}
	if f.logins.Load() != 2 {
		t.Fatalf("expected exactly one new login, got %d logins", f.logins.Load())
	}
}

func TestAFailedRenewalIsReportedAndRetriedOnTheNextRequest(t *testing.T) {
	c, f, now := rotatingFake(t)
	if err := profile(t, c); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(3 * time.Hour) // Token abgelaufen
	f.setLoginStatus(http.StatusServiceUnavailable)

	err := profile(t, c)
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != http.StatusServiceUnavailable {
		t.Fatalf("a failed renewal must reach the caller: %v", err)
	}
	if CredentialsRejected(err) {
		t.Fatal("an unavailable server is not a rejected API key")
	}

	f.setLoginStatus(0) // Vaultwarden ist wieder da
	if err := profile(t, c); err != nil {
		t.Fatalf("the next request must log in again by itself: %v", err)
	}
}

func TestRejectedCredentialsAreRecognised(t *testing.T) {
	c, _ := newFake(t, Credentials{ClientID: "user.1", ClientSecret: "wrong"})
	_, err := c.Login(context.Background())
	if !CredentialsRejected(err) {
		t.Fatalf("a rejected API key must be recognisable: %v", err)
	}
	if CredentialsRejected(&APIError{Method: "GET", Path: "/api/accounts/profile", Status: 401}) {
		t.Fatal("a 401 from the API is not a rejected API key")
	}
	if CredentialsRejected(&APIError{Method: "POST", Path: tokenPath, Body: "connection refused"}) {
		t.Fatal("a network error is not a rejected API key")
	}
}

func TestPingNeedsNoLogin(t *testing.T) {
	c, f := newFake(t, good)
	if err := c.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if f.logins.Load() != 0 {
		t.Fatal("ping must not log in")
	}
}
