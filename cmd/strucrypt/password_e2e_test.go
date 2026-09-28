// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// runInitWith runs `strucrypt init ...` in dir, with extraEnv added to the
// environment and stdin as the process's standard input — the two password
// paths that, unlike an argument, are not visible in the process list.
func runInitWith(t *testing.T, dir, pathEnv string, extraEnv []string, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, binName), append([]string{"init"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "PATH="+pathEnv), extraEnv...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// setupEncryptedOrigin bootstraps a repo holding one encrypted file and
// returns its path along with the plaintext that file must decrypt to.
func setupEncryptedOrigin(t *testing.T, pathEnv, password string) (string, string) {
	t.Helper()
	origin := newTestRepo(t, pathEnv)
	if out, err := runInitWith(t, origin, pathEnv, []string{passwordEnv + "=" + password}, ""); err != nil {
		t.Fatalf("bootstrap: %v\n%s", err, out)
	}
	runIn(t, origin, pathEnv, "strucrypt", "add", "file", "secrets/*.pem")

	if err := os.MkdirAll(filepath.Join(origin, "secrets"), 0o755); err != nil {
		t.Fatal(err)
	}
	plaintext := "-----BEGIN KEY-----\nsecret\n-----END KEY-----\n"
	if err := os.WriteFile(filepath.Join(origin, "secrets", "prod.pem"), []byte(plaintext), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, origin, pathEnv, "git", "add", ".")
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-m", "add secret")
	return origin, plaintext
}

func cloneOf(t *testing.T, pathEnv, origin string) string {
	t.Helper()
	parent := t.TempDir()
	clone := filepath.Join(parent, "clone")
	runIn(t, parent, pathEnv, "git", "clone", "-q", origin, clone)
	return clone
}

func assertDecrypted(t *testing.T, clone, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(clone, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("file after join = %q, want decrypted %q", got, want)
	}
}

// AC-7.10: a CI job must be able to bootstrap and join without a TTY and
// without putting the password on the command line, where every other user
// on the machine could read it out of the process list.
func TestInitTakesPasswordFromEnvironment(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	const password = "env-sourced-password"
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, password)

	clone := cloneOf(t, pathEnv, origin)
	out, err := runInitWith(t, clone, pathEnv, []string{passwordEnv + "=" + password}, "")
	if err != nil {
		t.Fatalf("join via %s: %v\n%s", passwordEnv, err, out)
	}
	assertDecrypted(t, clone, plaintext)
}

// AC-7.11: --password-stdin lets a password be piped straight from a secret
// store, never touching argv or the environment.
func TestInitTakesPasswordFromStdin(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	const password = "stdin-sourced-password"
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, password)

	clone := cloneOf(t, pathEnv, origin)
	// The trailing newline a pipeline or heredoc adds must not become part
	// of the password.
	out, err := runInitWith(t, clone, pathEnv, nil, password+"\n", "--password-stdin")
	if err != nil {
		t.Fatalf("join via --password-stdin: %v\n%s", err, out)
	}
	assertDecrypted(t, clone, plaintext)
}

// AC-7.12: a password on the command line is refused, with an error that
// names the supported inputs — it is the one path that leaks the shared
// password to other users on the machine, via the process list.
func TestInitRejectsPasswordArgument(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	const password = "argv-sourced-password"
	origin, _ := setupEncryptedOrigin(t, pathEnv, password)

	clone := cloneOf(t, pathEnv, origin)
	out, err := runInitWith(t, clone, pathEnv, nil, "", password)
	if err == nil {
		t.Fatalf("join with a password argument: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "process list") {
		t.Errorf("error does not explain the exposure:\n%s", out)
	}
	if _, err := runInExpectingError(t, clone, pathEnv, "git", "config", "--local", "--get", "filter.strucrypt.key"); err == nil {
		t.Error("a refused init registered a local key")
	}
}

// AC-7.13: with no password from any source and no terminal to prompt on,
// join fails and names the alternatives rather than hanging on a read or
// registering a filter with no key.
func TestInitWithoutAnyPasswordSourceFails(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "some-password")

	clone := cloneOf(t, pathEnv, origin)
	out, err := runInitWith(t, clone, pathEnv, nil, "")
	if err == nil {
		t.Fatalf("join with no password source: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, passwordEnv) {
		t.Errorf("error does not mention $%s as an alternative:\n%s", passwordEnv, out)
	}

	if _, err := os.Stat(filepath.Join(clone, "secrets", "prod.pem")); err != nil {
		t.Fatal(err)
	}
	if _, err := runInExpectingError(t, clone, pathEnv, "git", "config", "--local", "--get", "filter.strucrypt.key"); err == nil {
		t.Error("a failed init registered a local key")
	}
}
