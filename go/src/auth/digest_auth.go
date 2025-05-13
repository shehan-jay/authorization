package auth

import (
	"net/http"
)

// DigestAuth implements the Authenticator interface for Digest Authentication
type DigestAuth struct {
	BaseAuth
	Username string
	Password string
}

// NewDigestAuth creates a new DigestAuth instance
func NewDigestAuth(username, password string) *DigestAuth {
	return &DigestAuth{
		BaseAuth: BaseAuth{Type: DigestAuth},
		Username: username,
		Password: password,
	}
}

// Authenticate validates the Digest Authentication credentials
func (d *DigestAuth) Authenticate(r *http.Request) error {
	// TODO: Implement Digest validation
	return nil
}

// AddAuth adds Digest Authentication to the request
func (d *DigestAuth) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 