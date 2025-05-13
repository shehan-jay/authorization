package auth

import (
	"net/http"
)

// OAuth1 implements the Authenticator interface for OAuth 1.0 Authentication
type OAuth1 struct {
	BaseAuth
	ConsumerKey    string
	ConsumerSecret string
	Token          string
	TokenSecret    string
}

// NewOAuth1 creates a new OAuth1 instance
func NewOAuth1(consumerKey, consumerSecret, token, tokenSecret string) *OAuth1 {
	return &OAuth1{
		BaseAuth:      BaseAuth{Type: OAuth1},
		ConsumerKey:   consumerKey,
		ConsumerSecret: consumerSecret,
		Token:         token,
		TokenSecret:   tokenSecret,
	}
}

// Authenticate validates the OAuth 1.0 credentials
func (o *OAuth1) Authenticate(r *http.Request) error {
	// TODO: Implement OAuth 1.0 validation
	return nil
}

// AddAuth adds OAuth 1.0 Authentication to the request
func (o *OAuth1) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 