package main

import "testing"

func TestValidateService(t *testing.T) {
	tests := []struct {
		host, target string
		valid        bool
	}{
		{"app.example.com", "127.0.0.1:8081", true},
		{"remote.example.com", "10.77.0.20:80", true},
		{"evil.test", "10.77.0.20:80", false},
		{"app.example.com", "8.8.8.8:80", false},
		{"app.example.com", "10.77.0.20:99999", false},
		{"app.example.com", "localhost:8080/path", false},
	}
	for _, test := range tests {
		err := validateService(test.host, test.target, "example.com")
		if (err == nil) != test.valid {
			t.Errorf("validateService(%q, %q) error=%v, valid=%v", test.host, test.target, err, test.valid)
		}
	}
}
