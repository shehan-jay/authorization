package auth

import (
	"net/http"
	"testing"
)

func TestSAMLAuth(t *testing.T) {
	// Create a new SAMLAuth instance with test configuration
	auth := NewSAMLAuth(
		"test-entity-id",
		"test-assertion-consumer-service-url",
		"test-idp-sso-url",
		"test-idp-certificate",
	)

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid SAML assertion",
			Request: CreateTestRequest("POST", map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}, "SAMLResponse=test-saml-response"),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid SAML assertion",
			Request: CreateTestRequest("POST", map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}, "SAMLResponse=invalid-saml-response"),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Missing SAML response",
			Request: CreateTestRequest("POST", map[string]string{
				"Content-Type": "application/x-www-form-urlencoded",
			}, ""),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Invalid content type",
			Request: CreateTestRequest("POST", map[string]string{
				"Content-Type": "application/json",
			}, "{}"),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Invalid HTTP method",
			Request: CreateTestRequest("GET", nil),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			RunAuthTest(t, auth, tc)
		})
	}
}

func TestSAMLAuthGetType(t *testing.T) {
	auth := NewSAMLAuth("entity-id", "acs-url", "idp-url", "certificate")
	if auth.GetType() != "saml" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "saml")
	}
} 