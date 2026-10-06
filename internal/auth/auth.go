// Package auth implements the service's own login: one user with a bcrypt password hash,
// short-lived signed tokens, and a failed-login rate limit.
package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const issuer = "vwsync-api"

type Authenticator struct {
	user   [32]byte // SHA-256 of the user name, so the comparison has a fixed length
	hash   []byte
	secret []byte
	ttl    time.Duration
}

func New(user, bcryptHash string, secret []byte, ttl time.Duration) (*Authenticator, error) {
	if _, err := bcrypt.Cost([]byte(bcryptHash)); err != nil {
		return nil, errors.New("VWSYNC_PASSWORD_HASH is not a valid bcrypt hash (create one with: vwsync-api hash-password)")
	}
	return &Authenticator{user: sha256.Sum256([]byte(user)), hash: []byte(bcryptHash), secret: secret, ttl: ttl}, nil
}

// HashPassword creates the bcrypt hash for VWSYNC_PASSWORD_HASH.
func HashPassword(password string) (string, error) {
	// bcrypt only looks at the first 72 bytes; refuse instead of silently truncating.
	if len(password) > 72 {
		return "", errors.New("password is longer than 72 bytes (bcrypt limit)")
	}
	if len(password) < 12 {
		return "", errors.New("password must be at least 12 characters")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	return string(h), err
}

// Login checks the credentials and returns a token. The bcrypt comparison always runs, even for a
// wrong user name, so response time does not reveal whether the user name exists.
func (a *Authenticator) Login(user, password string) (token string, expires time.Time, ok bool) {
	given := sha256.Sum256([]byte(user))
	userOK := subtle.ConstantTimeCompare(given[:], a.user[:]) == 1
	passOK := bcrypt.CompareHashAndPassword(a.hash, []byte(password)) == nil
	if !userOK || !passOK {
		return "", time.Time{}, false
	}
	now := time.Now()
	expires = now.Add(a.ttl)
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    issuer,
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(expires),
	}).SignedString(a.secret)
	if err != nil {
		return "", time.Time{}, false
	}
	return token, expires, true
}

// Verify accepts only tokens signed with HS256 by this service and not yet expired.
func (a *Authenticator) Verify(token string) error {
	_, err := jwt.ParseWithClaims(token, &jwt.RegisteredClaims{}, func(*jwt.Token) (any, error) { return a.secret, nil },
		jwt.WithValidMethods([]string{"HS256"}), jwt.WithIssuer(issuer), jwt.WithExpirationRequired())
	return err
}
