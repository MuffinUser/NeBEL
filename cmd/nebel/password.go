// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// passwordEnv is the environment variable `init` reads the shared password
// from. Environment blocks are readable only by the process owner
// (/proc/<pid>/environ is 0600), unlike a command line, so this is the
// recommended non-interactive source.
const passwordEnv = "NEBEL_PASSWORD"

// ErrPasswordArgument is returned when a password is passed as a
// command-line argument. It is refused rather than accepted-with-a-warning:
// argv is world-readable on Linux via /proc/<pid>/cmdline, so any other
// local user can read the shared password while `init` runs, and shells and
// CI log echoes record it. A warning would leave the password just as
// exposed for everyone who didn't read it.
var ErrPasswordArgument = errors.New(`passwords are no longer accepted as command-line arguments:
  the argument is visible in the process list to every other user on this
  machine, and is recorded in shell history and CI logs. Use one of:
    NEBEL_PASSWORD="$SECRET" nebel init
    get-secret | nebel init --password-stdin
    nebel init                 (prompts)`)

// passwordInput is the set of password sources named on the command line.
type passwordInput struct {
	// fromStdin is --password-stdin: read the password from stdin, so it
	// can be piped from a secret store without ever becoming an argument.
	fromStdin bool
}

// resolve returns the password to use, consulting sources in order of
// decreasing safety: --password-stdin, then $NEBEL_PASSWORD, then an
// interactive no-echo prompt.
//
// required distinguishes the two init modes. Join mode needs a password and
// will prompt for one; bootstrap mode returns "" so the caller generates a
// strong one instead of asking the user to invent a weak one.
func (p passwordInput) resolve(required bool) (string, error) {
	if p.fromStdin {
		return readPasswordFromStdin()
	}
	if password := os.Getenv(passwordEnv); password != "" {
		return password, nil
	}
	if !required {
		return "", nil
	}
	return promptPassword()
}

func readPasswordFromStdin() (string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading password from stdin: %w", err)
	}
	// Trim only the line ending a pipeline or heredoc appends; a password
	// may legitimately contain leading or trailing spaces.
	password := strings.TrimRight(string(data), "\r\n")
	if password == "" {
		return "", fmt.Errorf("--password-stdin: no password on stdin")
	}
	return password, nil
}

// promptPassword reads a password from the terminal with echo disabled. It
// fails rather than falling back to an echoing read when there is no
// terminal — a non-interactive run that reaches this point has simply not
// been given a password, and silently reading from a redirected stdin would
// consume input the caller meant for something else.
func promptPassword() (string, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return "", fmt.Errorf("no password given and no terminal to prompt on: set $%s, pass --password-stdin, or run interactively", passwordEnv)
	}

	fmt.Fprint(os.Stderr, "Password: ")
	data, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", fmt.Errorf("reading password: %w", err)
	}
	password := string(data)
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	return password, nil
}
