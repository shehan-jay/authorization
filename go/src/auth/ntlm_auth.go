package auth

import (
	"net/http"
)

// NTLMAuth implements the Authenticator interface for NTLM Authentication
type NTLMAuth struct {
	BaseAuth
	Username string
	Password string
	Domain   string
}

// NewNTLMAuth creates a new NTLMAuth instance
func NewNTLMAuth(username, password, domain string) *NTLMAuth {
	return &NTLMAuth{
		BaseAuth: BaseAuth{Type: NTLMAuth},
		Username: username,
		Password: password,
		Domain:   domain,
	}
}

// Authenticate validates the NTLM Authentication
func (n *NTLMAuth) Authenticate(r *http.Request) error {
	// TODO: Implement NTLM validation
	return nil
}

// AddAuth adds NTLM Authentication to the request
func (n *NTLMAuth) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 