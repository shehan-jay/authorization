package auth

import (
	"net/http"
)

// AuthType represents the type of authentication
type AuthType string

const (
	NoAuth          AuthType = "none"
	BasicAuth       AuthType = "basic"
	BearerToken     AuthType = "bearer"
	JWTBearer       AuthType = "jwt"
	DigestAuth      AuthType = "digest"
	OAuth1          AuthType = "oauth1"
	OAuth2          AuthType = "oauth2"
	HawkAuth        AuthType = "hawk"
	AWSSignature    AuthType = "aws"
	NTLMAuth        AuthType = "ntlm"
	APIKey          AuthType = "apikey"
	AkamaiEdgeGrid  AuthType = "akamai"
	ASAPAuth        AuthType = "asap"
	OIDCAuth        AuthType = "oidc"
	SAMLAuth        AuthType = "saml"
)

// Authenticator defines the interface for all authentication methods
type Authenticator interface {
	// Authenticate authenticates the request
	Authenticate(r *http.Request) error
	// GetType returns the type of authentication
	GetType() AuthType
}

// BaseAuth provides common functionality for all auth implementations
type BaseAuth struct {
	Type AuthType
}

// GetType returns the authentication type
func (b *BaseAuth) GetType() AuthType {
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