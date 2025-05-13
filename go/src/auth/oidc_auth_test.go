package auth

import (
	"net/http"
	"testing"
)

func TestOIDCAuth(t *testing.T) {
	// Create a new OIDCAuth instance with test configuration
	auth := NewOIDCAuth(
		"test-issuer",
		"test-client-id",
		"test-client-secret",
		[]string{"test-audience"},
	)

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid ID token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer test-id-token",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid ID token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer invalid-id-token",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Missing Authorization header",
			Request: CreateTestRequest("GET", nil),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Malformed Authorization header",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Invalid Authorization scheme",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Basic dGVzdC11c2VyOnRlc3QtcGFzc3dvcmQ=",
			}),
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

func TestOIDCAuthGetType(t *testing.T) {
	auth := NewOIDCAuth("issuer", "client-id", "client-secret", []string{"audience"})
	if auth.GetType() != "oidc" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "oidc")
	}
} 