package auth

import (
	"net/http"
)

// Authenticator defines the interface for all authentication methods
type Authenticator interface {
	// Authenticate authenticates the request
	Authenticate(r *http.Request) error
	// GetType returns the type of authentication
	GetType() string
}

// BaseAuth provides common functionality for all auth implementations
type BaseAuth struct {
	Type string
}

// GetType returns the authentication type
func (b *BaseAuth) GetType() string {
	return b.Type
}

// RequiresAuth is a middleware that enforces authentication
func RequiresAuth(auth Authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := auth.Authenticate(r); err != nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
} 