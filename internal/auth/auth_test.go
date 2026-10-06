package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const pw = "a-long-test-password"

func newAuth(t *testing.T, ttl time.Duration) *Authenticator {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.MinCost) // production cost is far too slow for tests
	if err != nil {
		t.Fatal(err)
	}
	a, err := New("svc", string(h), []byte(strings.Repeat("s", 32)), ttl)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLoginAndVerify(t *testing.T) {
	a := newAuth(t, time.Minute)
	tok, _, ok := a.Login("svc", pw)
	if !ok || a.Verify(tok) != nil {
		t.Fatal("valid login rejected")
	}
	for _, c := range [][2]string{{"svc", "wrong"}, {"other", pw}, {"", ""}} {
		if _, _, ok := a.Login(c[0], c[1]); ok {
			t.Fatalf("accepted %v", c)
		}
	}
}

func TestVerifyRejectsForeignExpiredAndNoneAlgTokens(t *testing.T) {
	a := newAuth(t, time.Minute)
	sign := func(m jwt.SigningMethod, key any, exp time.Time, iss string) string {
		s, err := jwt.NewWithClaims(m, jwt.RegisteredClaims{Issuer: iss, ExpiresAt: jwt.NewNumericDate(exp)}).SignedString(key)
		if err != nil {
			t.Fatal(err)
		}
		return s
	}
	secret := []byte(strings.Repeat("s", 32))
	future := time.Now().Add(time.Minute)

	if a.Verify(sign(jwt.SigningMethodHS256, secret, future, issuer)) != nil {
		t.Fatal("control token rejected")
	}
	bad := map[string]string{
		"wrong secret": sign(jwt.SigningMethodHS256, []byte(strings.Repeat("x", 32)), future, issuer),
		"expired":      sign(jwt.SigningMethodHS256, secret, time.Now().Add(-time.Minute), issuer),
		"wrong issuer": sign(jwt.SigningMethodHS256, secret, future, "someone-else"),
		"other HMAC":   sign(jwt.SigningMethodHS512, secret, future, issuer),
		"alg none":     sign(jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType, future, issuer),
		"empty":        "",
	}
	for name, tok := range bad {
		if a.Verify(tok) == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestNewRejectsNonBcryptHash(t *testing.T) {
	if _, err := New("u", "plaintext-password", make([]byte, 32), time.Minute); err == nil {
		t.Fatal("a plain password must not be accepted as hash")
	}
}

func TestHashPasswordRules(t *testing.T) {
	if _, err := HashPassword("short"); err == nil {
		t.Fatal("short password accepted")
	}
	if _, err := HashPassword(strings.Repeat("a", 73)); err == nil {
		t.Fatal("password over 72 bytes accepted")
	}
}

func TestLimiter(t *testing.T) {
	now := time.Now()
	l := NewLimiter(3, time.Minute)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if blocked, _ := l.Blocked("a"); blocked {
			t.Fatalf("blocked after %d failures", i)
		}
		l.Fail("a")
	}
	if blocked, wait := l.Blocked("a"); !blocked || wait <= 0 || wait > time.Minute {
		t.Fatalf("not blocked: %v %v", blocked, wait)
	}
	if blocked, _ := l.Blocked("b"); blocked {
		t.Fatal("other key blocked")
	}
	now = now.Add(61 * time.Second)
	if blocked, _ := l.Blocked("a"); blocked {
		t.Fatal("still blocked after the window")
	}
	l.Fail("a")
	l.Reset("a")
	if len(l.failures) != 0 {
		t.Fatal("reset keeps state")
	}
}
