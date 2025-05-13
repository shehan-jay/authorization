package auth

import (
	"net/http"
	"testing"
)

func TestAWSSignature(t *testing.T) {
	// Create a new AWSSignature instance with test credentials
	auth := NewAWSSignature("test-access-key", "test-secret-key", "us-east-1")

	// Test cases
	tests := []TestCase{
		{
			Name: "Valid AWS signature",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 " +
					"Credential=test-access-key/20240101/us-east-1/s3/aws4_request, " +
					"SignedHeaders=host;x-amz-date, " +
					"Signature=test-signature",
				"X-Amz-Date": "20240101T000000Z",
			}),
			ExpectedStatus: http.StatusOK,
			ExpectedError:  false,
		},
		{
			Name: "Invalid access key",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 " +
					"Credential=wrong-access-key/20240101/us-east-1/s3/aws4_request, " +
					"SignedHeaders=host;x-amz-date, " +
					"Signature=test-signature",
				"X-Amz-Date": "20240101T000000Z",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Missing Authorization header",
			Request: CreateTestRequest("GET", map[string]string{
				"X-Amz-Date": "20240101T000000Z",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Missing X-Amz-Date header",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "AWS4-HMAC-SHA256 " +
					"Credential=test-access-key/20240101/us-east-1/s3/aws4_request, " +
					"SignedHeaders=host;x-amz-date, " +
					"Signature=test-signature",
			}),
			ExpectedStatus: http.StatusUnauthorized,
			ExpectedError:  true,
		},
		{
			Name: "Malformed Authorization header",
			Request: CreateTestRequest("GET", map[string]string{
				"Authorization": "AWS4-HMAC-SHA256",
				"X-Amz-Date":    "20240101T000000Z",
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

func TestAWSSignatureGetType(t *testing.T) {
	auth := NewAWSSignature("access-key", "secret-key", "region")
	if auth.GetType() != "aws" {
		t.Errorf("GetType() = %v, want %v", auth.GetType(), "aws")
	}
} 