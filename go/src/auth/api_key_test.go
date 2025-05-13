package auth

import (
	"net/http"
	"testing"
)

func TestAPIKey(t *testing.T) {
	// Create a new APIKey instance
	auth := NewAPIKey("valid_api_key")

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid API key in header",
			Request: CreateTestRequest("GET", map[string]string{
				"X-API-Key": "valid_api_key",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Valid API key in query",
			Request: func() *http.Request {
				req := CreateTestRequest("GET", nil)
				q := req.URL.Query()
				q.Add("api_key", "valid_api_key")
				req.URL.RawQuery = q.Encode()
				return req
			}(),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid API key",
			Request: CreateTestRequest("GET", map[string]string{
				"X-API-Key": "invalid_api_key",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name:           "Missing API key",
			Request:        CreateTestRequest("GET", nil),
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

func TestAPIKeyGetType(t *testing.T) {
	auth := NewAPIKey("key")
	if auth.GetType() != "apikey" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "apikey")
	}
} 