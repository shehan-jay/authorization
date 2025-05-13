package auth

import (
	"net/http"
)

// ASAPAuth implements the Authenticator interface for ASAP (Atlassian) Authentication
type ASAPAuth struct {
	BaseAuth
	Issuer     string
	Audience   string
	PrivateKey string
}

// NewASAPAuth creates a new ASAPAuth instance
func NewASAPAuth(issuer, audience, privateKey string) *ASAPAuth {
	return &ASAPAuth{
		BaseAuth:   BaseAuth{Type: ASAPAuth},
		Issuer:     issuer,
		Audience:   audience,
		PrivateKey: privateKey,
	}
}

// Authenticate validates the ASAP token
func (a *ASAPAuth) Authenticate(r *http.Request) error {
	// TODO: Implement ASAP validation
	return nil
}

// AddAuth adds ASAP token to the request
func (a *ASAPAuth) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 