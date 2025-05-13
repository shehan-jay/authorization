package auth

import (
	"net/http"
	"testing"
)

func TestOAuth2(t *testing.T) {
	// Create a new OAuth2 instance with test credentials
	auth := NewOAuth2("test-client-id", "test-client-secret")

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid access token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer valid-access-token",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid access token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer invalid-access-token",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Missing access token",
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
				"Authorization": "Basic valid-access-token",
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

func TestOAuth2GetType(t *testing.T) {
	auth := NewOAuth2("client-id", "client-secret")
	if auth.GetType() != "oauth2" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "oauth2")
	}
} 