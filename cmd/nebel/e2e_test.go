// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// binName is "nebel.exe" on Windows: git's filter driver invocation
// (filter.nebel.clean = "nebel clean %f") is resolved by the shell
// git uses internally, which follows PATHEXT — a bare extension-less
// "nebel" on PATH is not guaranteed to resolve the same way a real
// release binary (built with the .exe suffix) would.
var binName = "nebel"

func init() {
	if runtime.GOOS == "windows" {
		binName = "nebel.exe"
	}
}

// buildOnce compiles the nebel binary a single time for every e2e test
// in this package. runIn resolves "nebel" to this absolute path
// directly — exec.Command's PATH lookup happens against this process's own
// environment, not a child's cmd.Env, so a bare "nebel" name would
// never be found via cmd.Env alone. Child processes we spawn (git, and
// nebel's own git subprocess calls) still get binDir prepended to PATH
// in their environment, since git itself must find "nebel" on PATH
// when invoking the filter driver.
var (
	buildOnce sync.Once
	binDir    string
	buildErr  error
)

func ensureBinary(t *testing.T) string {
	t.Helper()
	buildOnce.Do(func() {
		binDir, buildErr = os.MkdirTemp("", "nebel-bin")
		if buildErr != nil {
			return
		}
		binPath := filepath.Join(binDir, binName)
		cmd := exec.Command("go", "build", "-o", binPath, ".")
		if out, err := cmd.CombinedOutput(); err != nil {
			buildErr = fmt.Errorf("go build: %w\n%s", err, out)
		}
	})
	if buildErr != nil {
		t.Fatalf("building nebel: %v", buildErr)
	}
	return binDir
}

// runIn runs name (git, or nebel) with args, in dir, with pathEnv as
// PATH for the child process.
func runIn(t *testing.T, dir, pathEnv, name string, args ...string) string {
	t.Helper()
	resolved := name
	if name == "nebel" {
		resolved = filepath.Join(binDir, binName)
	}
	cmd := exec.Command(resolved, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+pathEnv)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v (in %s): %v\n%s", name, args, dir, err, out)
	}
	return string(out)
}

// runInExpectingError is runIn's counterpart for calls expected to fail.
func runInExpectingError(t *testing.T, dir, pathEnv, name string, args ...string) (string, error) {
	t.Helper()
	resolved := name
	if name == "nebel" {
		resolved = filepath.Join(binDir, binName)
	}
	cmd := exec.Command(resolved, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "PATH="+pathEnv)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// registeredKeyValue returns the raw stored value (a base64-encoded key)
// for version in dir's local key storage, treating nebel as a black box
// rather than assuming which of its two storage locations actually holds
// it: the key file it writes to as of the 2026-09-29 audit's P06 fix
// (internal/localkey's keyFileName), checked first, falling back to the
// legacy git-config location a version could still be registered under —
// mirroring internal/localkey.Get's own precedence, so these tests keep
// working regardless of which one a given key landed in.
func registeredKeyValue(t *testing.T, dir, pathEnv string, version int) (string, bool) {
	t.Helper()
	commonDir := strings.TrimSpace(runIn(t, dir, pathEnv, "git", "rev-parse", "--git-common-dir"))
	if data, err := os.ReadFile(filepath.Join(dir, commonDir, "nebel-keys")); err == nil {
		prefix := fmt.Sprintf("%d=", version)
		for _, line := range strings.Split(string(data), "\n") {
			if val, ok := strings.CutPrefix(line, prefix); ok {
				return val, true
			}
		}
	}

	name := "filter.nebel.key"
	if version != 1 {
		name = fmt.Sprintf("filter.nebel.key%d", version)
	}
	val, ok, err := getLocalConfig(t, dir, pathEnv, name)
	if err != nil {
		return "", false
	}
	return val, ok
}

// initWithPassword runs `nebel init`, supplying the password through
// the environment — the command line no longer accepts one.
func initWithPassword(t *testing.T, dir, pathEnv, password string) {
	t.Helper()
	if out, err := runInitWith(t, dir, pathEnv, []string{passwordEnv + "=" + password}, ""); err != nil {
		t.Fatalf("nebel init (in %s): %v\n%s", dir, err, out)
	}
}

func newTestRepo(t *testing.T, pathEnv string) string {
	t.Helper()
	dir := t.TempDir()
	runIn(t, dir, pathEnv, "git", "init", "-q")
	runIn(t, dir, pathEnv, "git", "config", "user.email", "test@example.com")
	runIn(t, dir, pathEnv, "git", "config", "user.name", "test")
	return dir
}

func pathEnvWithBin(t *testing.T) string {
	dir := ensureBinary(t)
	return dir + string(os.PathListSeparator) + os.Getenv("PATH")
}

// AC-6.8: in a real git repository with .gitattributes wired to the filter
// and the local filter registered, git add + git commit + git checkout
// produce the expected encrypted blob in the object store and the expected
// decrypted content in the working tree.
func TestEndToEndWholeFileHappyPath(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)

	// Bootstrap: init with a fixed password (non-interactive, as CI would).
	initWithPassword(t, repo, pathEnv, "test-password-123")
	runIn(t, repo, pathEnv, "nebel", "add", "file", "secrets/*.pem")

	secretsDir := filepath.Join(repo, "secrets")
	if err := os.MkdirAll(secretsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plaintext := "-----BEGIN KEY-----\ntotally-secret\n-----END KEY-----\n"
	secretPath := filepath.Join(secretsDir, "prod.pem")
	if err := os.WriteFile(secretPath, []byte(plaintext), 0o644); err != nil {
		t.Fatal(err)
	}

	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "add secret")

	// The blob stored in git's object database must be ciphertext, not
	// the original plaintext.
	stored := runIn(t, repo, pathEnv, "git", "show", "HEAD:secrets/prod.pem")
	if stored == plaintext {
		t.Error("blob committed to git is plaintext, expected ENC[...] ciphertext")
	}
	if !bytes.HasPrefix([]byte(stored), []byte("ENC[")) {
		t.Errorf("committed blob is not a well-formed ENC[...] tag: %q", stored)
	}

	// The working tree file must remain decrypted throughout.
	onDisk, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != plaintext {
		t.Errorf("working tree file after commit = %q, want plaintext %q", onDisk, plaintext)
	}

	// Force a real checkout round-trip: remove the working tree file and
	// restore it from the git object just committed, going through smudge.
	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	runIn(t, repo, pathEnv, "git", "checkout", "--", "secrets/prod.pem")

	restored, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != plaintext {
		t.Errorf("checked-out file = %q, want %q", restored, plaintext)
	}
}

// AC-6.6 / AC-7.8: a fresh clone that has not run `nebel init` sees
// ciphertext passthrough (no local key, no error, no filter applied);
// joining with the correct password then re-decrypts it in place.
func TestCloneWithoutInitStaysEncrypted(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin := newTestRepo(t, pathEnv)
	runIn(t, origin, pathEnv, "git", "config", "receive.denyCurrentBranch", "updateInstead")
	initWithPassword(t, origin, pathEnv, "test-password-123")
	runIn(t, origin, pathEnv, "nebel", "add", "file", "secrets/*.pem")

	secretsDir := filepath.Join(origin, "secrets")
	if err := os.MkdirAll(secretsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plaintext := "super-secret"
	if err := os.WriteFile(filepath.Join(secretsDir, "prod.pem"), []byte(plaintext), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, origin, pathEnv, "git", "add", ".")
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-m", "add secret")

	// Clone fresh: the clone has .nebel.yaml (committed) but nobody has
	// run `nebel init` there yet, so no local key is registered.
	cloneDir := t.TempDir()
	clonePath := filepath.Join(cloneDir, "clone")
	runIn(t, cloneDir, pathEnv, "git", "clone", "-q", origin, clonePath)

	got, err := os.ReadFile(filepath.Join(clonePath, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) == plaintext {
		t.Error("clone without nebel init decrypted content it should not have been able to")
	}
	if !bytes.HasPrefix(got, []byte("ENC[")) {
		t.Errorf("clone without init: expected ciphertext passthrough, got %q", got)
	}

	// Now join with the correct password: the file must be re-checked-out
	// and decrypted (AC-7.8).
	initWithPassword(t, clonePath, pathEnv, "test-password-123")

	joined, err := os.ReadFile(filepath.Join(clonePath, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(joined) != plaintext {
		t.Errorf("after join, file = %q, want decrypted %q", joined, plaintext)
	}
}

// AC-7.7: joining with the wrong password fails and does not register the
// filter, leaving the clone in the no-key passthrough state.
func TestJoinWithWrongPasswordFails(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "correct-password")

	keyBefore, _ := registeredKeyValue(t, repo, pathEnv, 1)

	out, err := runInitWith(t, repo, pathEnv, []string{passwordEnv + "=wrong-password"}, "")
	if err == nil {
		t.Fatalf("nebel init with wrong password: want an error, got success: %s", out)
	}

	keyAfter, _ := registeredKeyValue(t, repo, pathEnv, 1)
	if keyBefore != keyAfter {
		t.Error("wrong password changed the registered local key")
	}
}
