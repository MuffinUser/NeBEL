// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"strings"
	"testing"
)

// The password must never become a command-line argument: argv is
// world-readable on Linux, so any other local user can read the shared
// password out of the process list while init runs. These tests pin the
// input precedence that makes that possible.
func TestResolvePasswordPrecedence(t *testing.T) {
	tests := []struct {
		name  string
		env   string
		input passwordInput
		want  string
	}{
		{"environment", "from-env", passwordInput{}, "from-env"},
		// An empty variable is treated as unset: exporting
		// STRUCRYPT_PASSWORD="" in CI is a missing secret, not a password.
		{"empty environment falls through to the prompt", "", passwordInput{}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(passwordEnv, tt.env)

			// required=false so the "nothing supplied one" case returns
			// rather than trying to open a terminal that isn't there.
			got, err := tt.input.resolve(false)
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
		{"stdin flag", []string{"--password-stdin"}, passwordInput{fromStdin: true}, false},
		{"unknown flag", []string{"--password", "hunter2"}, passwordInput{}, true},
		{"positional password", []string{"hunter2"}, passwordInput{}, true},
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

// A password argument is refused outright, with an error that names the
// supported inputs — accepting it with a warning would leave the password
// just as exposed for everyone who didn't read the warning.
func TestParseInitArgsRejectsPasswordArgument(t *testing.T) {
	_, err := parseInitArgs([]string{"hunter2"})
	if !errors.Is(err, ErrPasswordArgument) {
		t.Fatalf("parseInitArgs() error = %v, want %v", err, ErrPasswordArgument)
	}
	for _, want := range []string{passwordEnv, "--password-stdin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error does not point at %q:\n%s", want, err)
		}
	}
}
