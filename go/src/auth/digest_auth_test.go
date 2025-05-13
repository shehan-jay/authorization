package auth

import (
	"net/http"
	"testing"
)

func TestDigestAuth(t *testing.T) {
	// Create a new DigestAuth instance with test credentials
	auth := NewDigestAuth("test-realm", map[string]string{
		"test-user": "test-password",
	})

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid digest credentials",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Digest username=\"test-user\"," +
					"realm=\"test-realm\"," +
					"nonce=\"test-nonce\"," +
					"uri=\"/\"," +
					"response=\"test-response\"," +
					"algorithm=MD5," +
					"qop=auth," +
					"nc=00000001," +
					"cnonce=\"test-cnonce\"",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid username",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "Digest username=\"wrong-user\"," +
					"realm=\"test-realm\"," +
					"nonce=\"test-nonce\"," +
					"uri=\"/\"," +
					"response=\"test-response\"," +
					"algorithm=MD5," +
					"qop=auth," +
					"nc=00000001," +
					"cnonce=\"test-cnonce\"",
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
				"Authorization": "Digest",
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

func TestDigestAuthGetType(t *testing.T) {
	auth := NewDigestAuth("realm", map[string]string{"user": "pass"})
	if auth.GetType() != "digest" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "digest")
	}
} 