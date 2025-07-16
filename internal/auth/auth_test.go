package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	headerValidKey := http.Header{}
	headerValidKey.Add("Authorization", "ApiKey MOCK_API_KEY")
	headerMalformedKey := http.Header{}
	headerMalformedKey.Add("Authorization", "MOCK_API_KEY")
	headerNoKey := http.Header{}

	tests := []struct {
		name          string
		input         http.Header
		expectedKey   string
		expectedError error
	}{
		{
			name:          "successful",
			input:         headerValidKey,
			expectedKey:   "MOCK_API_KEY",
			expectedError: nil,
		},
		{
			name:          "malformed key",
			input:         headerMalformedKey,
			expectedKey:   "",
			expectedError: errors.New("malformed authorization header"),
		},
		{
			name:          "no key",
			input:         headerNoKey,
			expectedKey:   "",
			expectedError: ErrNoAuthHeaderIncluded,
		},
	}
	for _, tt := range tests {
		actualKey, actualErr := GetAPIKey(tt.input)
		if tt.expectedError != nil {
			if actualErr == nil {
				t.Fatalf("(case %s) expect error %v but got none", tt.name, tt.expectedError)
			}
			if tt.expectedError.Error() == actualErr.Error() {
				continue
			} else {
				t.Fatalf("(case %s) expect error %v but got error %v", tt.name, tt.expectedError, actualErr)
			}
		}
		if actualErr != nil {
			t.Fatalf("(case %s) unexpected error %v", tt.name, actualErr)
		}
		if actualKey != tt.expectedKey {
			t.Fatalf("(case %s) expect parsed key %s but got %s", tt.name, tt.expectedKey, actualKey)
		}
	}

}
