package auth

import (
	"net/http"
)

// AWSSignature implements the Authenticator interface for AWS Signature Authentication
type AWSSignature struct {
	BaseAuth
	AccessKey string
	SecretKey string
	Region    string
	Service   string
}

// NewAWSSignature creates a new AWSSignature instance
func NewAWSSignature(accessKey, secretKey, region, service string) *AWSSignature {
	return &AWSSignature{
		BaseAuth:  BaseAuth{Type: AWSSignature},
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    region,
		Service:   service,
	}
}

// Authenticate validates the AWS Signature
func (a *AWSSignature) Authenticate(r *http.Request) error {
	// TODO: Implement AWS Signature validation
	return nil
}

// AddAuth adds AWS Signature to the request
func (a *AWSSignature) AddAuth(r *http.Request) {
	// TODO: Add Authorization header
} 