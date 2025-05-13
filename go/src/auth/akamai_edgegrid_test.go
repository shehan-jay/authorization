package auth

import (
	"net/http"
	"testing"
)

func TestAkamaiEdgeGrid(t *testing.T) {
	// Create a new AkamaiEdgeGrid instance with test credentials
	auth := NewAkamaiEdgeGrid("test-client-token", "test-client-secret", "test-access-token")

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid EdgeGrid credentials",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "EG1-HMAC-SHA256 client_token=test-client-token;" +
					"access_token=test-access-token;" +
					"timestamp=20240101T00:00:00+0000;" +
					"nonce=test-nonce;" +
					"signature=test-signature",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid client token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "EG1-HMAC-SHA256 client_token=wrong-client-token;" +
					"access_token=test-access-token;" +
					"timestamp=20240101T00:00:00+0000;" +
					"nonce=test-nonce;" +
					"signature=test-signature",
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
				"Authorization": "EG1-HMAC-SHA256",
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

func TestAkamaiEdgeGridGetType(t *testing.T) {
	auth := NewAkamaiEdgeGrid("client-token", "client-secret", "access-token")
	if auth.GetType() != "akamai" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "akamai")
	}
} 