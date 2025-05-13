package auth

import (
	"net/http"
)

// AkamaiEdgeGrid implements the Authenticator interface for Akamai EdgeGrid Authentication
type AkamaiEdgeGrid struct {
	BaseAuth
	ClientToken  string
	ClientSecret string
	AccessToken  string
	Host         string
}

// NewAkamaiEdgeGrid creates a new AkamaiEdgeGrid instance
func NewAkamaiEdgeGrid(clientToken, clientSecret, accessToken, host string) *AkamaiEdgeGrid {
	return &AkamaiEdgeGrid{
		BaseAuth:     BaseAuth{Type: AkamaiEdgeGrid},
		ClientToken:  clientToken,
		ClientSecret: clientSecret,
		AccessToken:  accessToken,
		Host:         host,
	}
}

// Authenticate validates the Akamai EdgeGrid signature
func (a *AkamaiEdgeGrid) Authenticate(r *http.Request) error {
	// TODO: Implement Akamai EdgeGrid validation
	return nil
}

// AddAuth adds Akamai EdgeGrid signature to the request
func (a *AkamaiEdgeGrid) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 