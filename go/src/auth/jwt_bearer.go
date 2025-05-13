package auth

import (
	"net/http"
)

// JWTBearer implements the Authenticator interface for JWT Bearer Authentication
type JWTBearer struct {
	BaseAuth
	Secret string
}

// NewJWTBearer creates a new JWTBearer instance
func NewJWTBearer(secret string) *JWTBearer {
	return &JWTBearer{
		BaseAuth: BaseAuth{Type: JWTBearer},
		Secret:   secret,
	}
}

// Authenticate validates the JWT Bearer token
func (j *JWTBearer) Authenticate(r *http.Request) error {
	// TODO: Implement JWT validation
	return nil
}

// AddAuth adds JWT Bearer token to the request
func (j *JWTBearer) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 