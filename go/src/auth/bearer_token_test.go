package auth

import (
	"net/http"
	"testing"
)

func TestBearerToken(t *testing.T) {
	// Create a new BearerToken instance
	auth := NewBearerToken("valid_token")

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer valid_token",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid token",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer invalid_token",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name:           "Missing token",
			Request:        CreateTestRequest("GET", nil),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Malformed header",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer",
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

func TestBearerTokenGetType(t *testing.T) {
	auth := NewBearerToken("token")
	if auth.GetType() != "bearer" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "bearer")
	}
} 