package auth

import (
	"net/http"
)

// NoAuth implements the Authenticator interface for no authentication
type NoAuth struct {
	BaseAuth
}

// NewNoAuth creates a new NoAuth instance
func NewNoAuth() *NoAuth {
	return &NoAuth{
		BaseAuth: BaseAuth{
			Type: NoAuth,
		},
	}
}

// Authenticate always returns nil as no authentication is required
func (n *NoAuth) Authenticate(r *http.Request) error {
	return nil
} 