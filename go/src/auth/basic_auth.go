package auth

import (
	"encoding/base64"
	"net/http"
	"strings"
)

// BasicAuth implements the Authenticator interface for Basic Authentication
type BasicAuth struct {
	BaseAuth
	Username string
	Password string
}

// NewBasicAuth creates a new BasicAuth instance
func NewBasicAuth(username, password string) *BasicAuth {
	return &BasicAuth{
		BaseAuth: BaseAuth{
			Type: BasicAuth,
		},
		Username: username,
		Password: password,
	}
}

// Authenticate validates the Basic Authentication credentials
func (b *BasicAuth) Authenticate(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ErrMissingAuth
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 || parts[0] != "Basic" {
		return ErrInvalidAuth
	}

	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return ErrInvalidAuth
	}

	pair := strings.SplitN(string(payload), ":", 2)
	if len(pair) != 2 {
		return ErrInvalidAuth
	}

	if pair[0] != b.Username || pair[1] != b.Password {
		return ErrInvalidCredentials
	}

	return nil
}

// AddAuth adds Basic Authentication to the request
func (b *BasicAuth) AddAuth(r *http.Request) {
	auth := base64.StdEncoding.EncodeToString([]byte(b.Username + ":" + b.Password))
	r.Header.Set("Authorization", "Basic "+auth)
} 