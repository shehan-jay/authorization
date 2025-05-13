package auth

import (
	"net/http"
)

// APIKey implements the Authenticator interface for API Key Authentication
type APIKey struct {
	BaseAuth
	Key string
}

// NewAPIKey creates a new APIKey instance
func NewAPIKey(key string) *APIKey {
	return &APIKey{
		BaseAuth: BaseAuth{Type: APIKey},
		Key:      key,
	}
}

// Authenticate validates the API Key
func (a *APIKey) Authenticate(r *http.Request) error {
	// TODO: Implement API Key validation
	return nil
}

// AddAuth adds API Key to the request
func (a *APIKey) AddAuth(r *http.Request) {
	// TODO: Add API Key header
} 