package auth

import (
	"net/http"
	"testing"
)

func TestNoAuth(t *testing.T) {
	// Create a new NoAuth instance
	auth := NewNoAuth()

	// Test cases
	tests := []TestCase{
		{
			Name:           "No authentication required",
			Request:        CreateTestRequest("GET", nil),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Request with headers",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Bearer test-token",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Request with query parameters",
			Request: CreateTestRequest("GET", map[string]string{
				"X-API-Key": "test-api-key",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.Name, func(t *testing.T) {
			RunAuthTest(t, auth, tc)
		})
	}
}

func TestNoAuthGetType(t *testing.T) {
	auth := NewNoAuth()
	if auth.GetType() != "none" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "none")
	}
} 