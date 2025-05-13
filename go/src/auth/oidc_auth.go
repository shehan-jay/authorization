package auth

import (
	"net/http"
)

// OIDCAuth implements the Authenticator interface for OpenID Connect Authentication
type OIDCAuth struct {
	BaseAuth
	ClientID     string
	ClientSecret string
	Issuer       string
}

// NewOIDCAuth creates a new OIDCAuth instance
func NewOIDCAuth(clientID, clientSecret, issuer string) *OIDCAuth {
	return &OIDCAuth{
		BaseAuth:     BaseAuth{Type: OIDCAuth},
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Issuer:       issuer,
	}
}

// Authenticate validates the OIDC token
func (o *OIDCAuth) Authenticate(r *http.Request) error {
	// TODO: Implement OIDC validation
	return nil
}

// AddAuth adds OIDC token to the request
func (o *OIDCAuth) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 