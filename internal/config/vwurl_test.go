package config

import (
	"strings"
	"testing"
)

func TestVaultwardenURLMustUseHTTPSExceptOnThisMachine(t *testing.T) {
	cases := map[string]bool{
		"https://vault.example.com":      true,
		"https://vault.example.com:8443": true,
		"https://10.1.2.3":               true,
		"http://localhost:8000":          true,
		"http://127.0.0.1:18082":         true,
		"http://[::1]:8000":              true,
		"http://vault.example.com":       false,
		"http://10.1.2.3":                false,
		"http://127.0.0.1.example.com":   false, // looks local, is not
		"ftp://vault.example.com":        false,
		"vault.example.com":              false,
		"https://":                       false,
	}
	for raw, ok := range cases {
		valid(t)
		t.Setenv("VW_URL", raw)
		_, err := FromEnv()
		if ok && err != nil {
			t.Errorf("%s rejected: %v", raw, err)
		}
		if !ok && err == nil {
			t.Errorf("%s accepted", raw)
		}
		if !ok && err != nil && !strings.Contains(err.Error(), "VW_URL") {
			t.Errorf("%s: message does not name the variable: %v", raw, err)
		}
	}
}

func TestPlainHTTPMessageExplainsTheRule(t *testing.T) {
	valid(t)
	t.Setenv("VW_URL", "http://vault.example.com")
	_, err := FromEnv()
	if err == nil || !strings.Contains(err.Error(), "https") || !strings.Contains(err.Error(), "localhost") {
		t.Fatalf("%v", err)
	}
}

func TestCAFileIsPassedThrough(t *testing.T) {
	valid(t)
	t.Setenv("VW_CA_FILE", "/etc/vwsync-api/ca.pem")
	c, err := FromEnv()
	if err != nil || c.VWCAFile != "/etc/vwsync-api/ca.pem" {
		t.Fatalf("%+v %v", c, err)
	}
}
