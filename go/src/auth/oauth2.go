package auth

import (
	"net/http"
)

// OAuth2 implements the Authenticator interface for OAuth 2.0 Authentication
type OAuth2 struct {
	BaseAuth
	AccessToken string
}

// NewOAuth2 creates a new OAuth2 instance
func NewOAuth2(accessToken string) *OAuth2 {
	return &OAuth2{
		BaseAuth:    BaseAuth{Type: OAuth2},
		AccessToken: accessToken,
	}
}

// Authenticate validates the OAuth 2.0 access token
func (o *OAuth2) Authenticate(r *http.Request) error {
	// TODO: Implement OAuth 2.0 validation
	return nil
}

// AddAuth adds OAuth 2.0 Bearer token to the request
func (o *OAuth2) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 