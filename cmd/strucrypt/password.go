package main

import (
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
const passwordEnv = "STRUCRYPT_PASSWORD"

// argvWarning is printed when a password arrives as a command-line
// argument. The argument stays supported — removing it would break existing
// CI jobs — but it is the one input path that leaks: argv is world-readable
// on Linux via /proc/<pid>/cmdline, so any other local user can read the
// shared password while `init` runs, and shells and CI log echoes record it.
const argvWarning = `strucrypt: warning: passing the password as a command-line argument exposes it
  to every other user on this machine (it is visible in the process list) and
  to shell history and CI logs. Use $` + passwordEnv + `, --password-stdin, or
  the interactive prompt instead.`

// passwordInput is the set of password sources named on the command line.
type passwordInput struct {
	// arg is a positional password argument, empty if not given.
	arg string

	// fromStdin is --password-stdin: read the password from stdin, so it
	// can be piped from a secret store without ever becoming an argument.
	fromStdin bool
}

// resolve returns the password to use, consulting sources in order of
// decreasing safety: --password-stdin, then $STRUCRYPT_PASSWORD, then a
// positional argument (with a warning), then an interactive no-echo prompt.
//
// required distinguishes the two init modes. Join mode needs a password and
// will prompt for one; bootstrap mode returns "" so the caller generates a
// strong one instead of asking the user to invent a weak one.
func (p passwordInput) resolve(required bool) (string, error) {
	if p.fromStdin {
		if p.arg != "" {
			return "", fmt.Errorf("--password-stdin and a password argument are mutually exclusive")
		}
		return readPasswordFromStdin()
	}
	if password := os.Getenv(passwordEnv); password != "" {
		return password, nil
	}
	if p.arg != "" {
		fmt.Fprintln(os.Stderr, argvWarning)
		return p.arg, nil
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
