package auth

import (
	"net/http"
	"testing"
)

func TestNTLMAuth(t *testing.T) {
	// Create a new NTLMAuth instance with test credentials
	auth := NewNTLMAuth("test-domain", map[string]string{
		"test-user": "test-password",
	})

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid NTLM credentials",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid username",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "NTLM TlRMTVNTUAABAAAAB4IIogAAAAAAAAAAAAAAAAAAAAAGAbEdAAAADw==",
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
				"Authorization": "NTLM",
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

func TestNTLMAuthGetType(t *testing.T) {
	auth := NewNTLMAuth("domain", map[string]string{"user": "pass"})
	if auth.GetType() != "ntlm" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "ntlm")
	}
} 