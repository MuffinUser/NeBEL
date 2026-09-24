package main

import (
	"strings"
	"testing"
)

// The password must reach `init` without ever becoming a command-line
// argument: argv is world-readable on Linux, so any other local user can
// read the shared password out of the process list while init runs.
// These tests pin the input precedence that makes that possible.
func TestResolvePasswordPrecedence(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		input passwordInput
		want  string
	}{
		{"environment", "from-env", passwordInput{}, "from-env"},
		{"environment beats argument", "from-env", passwordInput{arg: "from-argv"}, "from-env"},
		// An empty variable is treated as unset: exporting
		// STRUCRYPT_PASSWORD="" in CI is a missing secret, not a password.
		{"argument when nothing safer is set", "", passwordInput{arg: "from-argv"}, "from-argv"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(passwordEnv, tt.env)

			got, err := tt.input.resolve(true)
			if err != nil {
				t.Fatalf("resolve: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolve() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Bootstrap mode must not prompt when no password is supplied: it generates
// a strong one instead of asking the user to invent a weak one (AC-7.2).
func TestResolvePasswordOptionalReturnsEmpty(t *testing.T) {
	t.Setenv(passwordEnv, "")

	got, err := passwordInput{}.resolve(false)
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if got != "" {
		t.Errorf("resolve() = %q, want \"\" so the caller generates a password", got)
	}
}

func TestParseInitArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    passwordInput
		wantErr bool
	}{
		{"no arguments", nil, passwordInput{}, false},
		{"positional password", []string{"hunter2"}, passwordInput{arg: "hunter2"}, false},
		{"stdin flag", []string{"--password-stdin"}, passwordInput{fromStdin: true}, false},
		{"unknown flag", []string{"--password", "hunter2"}, passwordInput{}, true},
		{"two positionals", []string{"a", "b"}, passwordInput{}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseInitArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseInitArgs(%q): want an error, got %+v", tt.args, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInitArgs(%q): %v", tt.args, err)
			}
			if got != tt.want {
				t.Errorf("parseInitArgs(%q) = %+v, want %+v", tt.args, got, tt.want)
			}
		})
	}
}

// --password-stdin and a positional password name two different passwords;
// silently preferring one would be a confusing way to fail.
func TestResolveRejectsStdinWithArgument(t *testing.T) {
	t.Setenv(passwordEnv, "")

	if _, err := (passwordInput{arg: "hunter2", fromStdin: true}).resolve(true); err == nil {
		t.Error("resolve() with both --password-stdin and an argument: want an error, got nil")
	} else if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("resolve() error = %v, want it to explain the conflict", err)
	}
}
