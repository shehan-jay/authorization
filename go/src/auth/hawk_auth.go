package auth

import (
	"net/http"
)

// HawkAuth implements the Authenticator interface for Hawk Authentication
type HawkAuth struct {
	BaseAuth
	ID        string
	Key       string
	Algorithm string
}

// NewHawkAuth creates a new HawkAuth instance
func NewHawkAuth(id, key, algorithm string) *HawkAuth {
	return &HawkAuth{
		BaseAuth:  BaseAuth{Type: HawkAuth},
		ID:        id,
		Key:       key,
		Algorithm: algorithm,
	}
}

// Authenticate validates the Hawk Authentication header
func (h *HawkAuth) Authenticate(r *http.Request) error {
	// TODO: Implement Hawk validation
	return nil
}

// AddAuth adds Hawk Authentication to the request
func (h *HawkAuth) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 