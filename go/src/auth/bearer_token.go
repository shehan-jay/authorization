package auth

import (
	"net/http"
	"strings"
)

// BearerToken implements the Authenticator interface for Bearer Token Authentication
type BearerToken struct {
	BaseAuth
	Token string
}

// NewBearerToken creates a new BearerToken instance
func NewBearerToken(token string) *BearerToken {
	return &BearerToken{
		BaseAuth: BaseAuth{
			Type: BearerToken,
		},
		Token: token,
	}
}

// Authenticate validates the Bearer Token
func (b *BearerToken) Authenticate(r *http.Request) error {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return ErrMissingAuth
	}

	parts := strings.Split(auth, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return ErrInvalidAuth
	}

	if parts[1] != b.Token {
		return ErrInvalidCredentials
	}

	return nil
}

// AddAuth adds Bearer Token to the request
func (b *BearerToken) AddAuth(r *http.Request) {
	r.Header.Set("Authorization", "Bearer "+b.Token)
} 