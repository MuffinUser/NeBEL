// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const stagingYAML = `# Staging configuration.
database:
  host: db.internal      # not a secret
  password: "s3cr3t"
  port: 5432
api:
  keys: [alpha, beta]
`

// setupValueRepo bootstraps a repo containing config/staging.yaml.
func setupValueRepo(t *testing.T, pathEnv string) string {
	t.Helper()
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "value-mode-password")

	if err := os.MkdirAll(filepath.Join(repo, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "config", "staging.yaml"), []byte(stagingYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

// AC-8.2: `add field` with paths on the command line creates a mode: value
// rule, and git then encrypts exactly those values.
func TestAddFieldEncryptsOnlyNamedValues(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)

	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password", "api.keys[0]")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt fields")

	stored := runIn(t, repo, pathEnv, "git", "show", "HEAD:config/staging.yaml")
	if strings.Contains(stored, "s3cr3t") || strings.Contains(stored, "alpha") {
		t.Errorf("a named value was committed in plaintext:\n%s", stored)
	}
	for _, kept := range []string{"# Staging configuration.", "host: db.internal      # not a secret", "port: 5432", "beta"} {
		if !strings.Contains(stored, kept) {
			t.Errorf("unrelated content %q did not survive:\n%s", kept, stored)
		}
	}

	// The working tree stays readable, and a checkout restores it.
	onDisk, err := os.ReadFile(filepath.Join(repo, "config", "staging.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != stagingYAML {
		t.Errorf("working tree changed after commit:\n got  = %q\n want = %q", onDisk, stagingYAML)
	}

	// Determinism: nothing to commit after a fresh checkout.
	if err := os.Remove(filepath.Join(repo, "config", "staging.yaml")); err != nil {
		t.Fatal(err)
	}
	runIn(t, repo, pathEnv, "git", "checkout", "--", "config/staging.yaml")
	if status := runIn(t, repo, pathEnv, "git", "status", "--porcelain"); strings.TrimSpace(status) != "" {
		t.Errorf("checkout left the tree dirty, so clean is not deterministic:\n%s", status)
	}
}

// AC-8.5: re-running with the same field changes nothing.
func TestAddFieldIsIdempotent(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)
	configPath := filepath.Join(repo, ".nebel.yaml")

	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	first, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}

	out := runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	second, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Errorf("re-adding the same field rewrote the config:\n first  = %s\n second = %s", first, second)
	}
	if !strings.Contains(out, "No new fields") {
		t.Errorf("re-adding should say nothing changed, got: %s", out)
	}
}

// A path that isn't in the file is refused when the rule is written, not
// later on whoever first stages the file.
func TestAddFieldRejectsMissingPath(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)

	out, err := runInExpectingError(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.nope")
	if err == nil {
		t.Fatalf("add field with a missing path: want an error, got:\n%s", out)
	}
	if !strings.Contains(out, "database.nope") {
		t.Errorf("error does not name the path:\n%s", out)
	}

	config, err := os.ReadFile(filepath.Join(repo, ".nebel.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(config), "staging.yaml") {
		t.Errorf("a rejected path still wrote a rule:\n%s", config)
	}
}

// The two subcommands write different rules for the same path, so mixing
// them is refused rather than silently reinterpreting one as the other.
func TestAddFileAndFieldConflict(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)

	runIn(t, repo, pathEnv, "nebel", "add", "file", "config/staging.yaml")
	out, err := runInExpectingError(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	if err == nil {
		t.Fatalf("add field over a mode: file rule: want an error, got:\n%s", out)
	}
	if !strings.Contains(out, "mode") {
		t.Errorf("error does not explain the mode conflict:\n%s", out)
	}
}

// With no paths and no terminal, the picker can't run; the error has to
// say what to do instead of hanging or silently doing nothing.
func TestAddFieldWithoutTerminalExplainsItself(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)

	out, err := runInExpectingError(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml")
	if err == nil {
		t.Fatalf("add field with no paths and no terminal: want an error, got:\n%s", out)
	}
	if !strings.Contains(out, "pass the paths as arguments") {
		t.Errorf("error does not suggest passing paths:\n%s", out)
	}
}

// `add` with no subcommand, or an unknown one, prints usage rather than
// guessing which kind of rule was meant.
func TestAddRequiresSubcommand(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)

	for _, args := range [][]string{{"add"}, {"add", "secrets/*.pem"}} {
		out, err := runInExpectingError(t, repo, pathEnv, "nebel", args...)
		if err == nil {
			t.Errorf("nebel %v: want an error, got:\n%s", args, out)
		}
		if !strings.Contains(out, "add file") || !strings.Contains(out, "add field") {
			t.Errorf("nebel %v: usage does not list both subcommands:\n%s", args, out)
		}
	}
}

// Joining a repo whose .gitattributes was never committed leaves every
// value encrypted: git has no filter assignment, so smudge never runs.
// The password is correct and the key registers fine, so without a count
// this is indistinguishable from a successful join — init has to say that
// it decrypted nothing, and why.
func TestJoinReportsWhenNothingIsFilterManaged(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin := setupValueRepo(t, pathEnv)
	runIn(t, origin, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")

	// Commit everything except .gitattributes.
	runIn(t, origin, pathEnv, "git", "add", ".nebel.yaml", "config/staging.yaml")
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-m", "without .gitattributes")

	cloneDir := t.TempDir()
	clone := filepath.Join(cloneDir, "clone")
	runIn(t, cloneDir, pathEnv, "git", "clone", "-q", origin, clone)

	out, err := runInitWith(t, clone, pathEnv, []string{passwordEnv + "=value-mode-password"}, "")
	if err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no filter-managed files") {
		t.Errorf("join decrypted nothing but did not say so:\n%s", out)
	}
	if !strings.Contains(out, gitattributesName) {
		t.Errorf("the hint does not name %s:\n%s", gitattributesName, out)
	}
}

// The normal case reports how many files it decrypted, so a join that
// silently covered fewer files than expected is visible.
func TestJoinReportsDecryptedCount(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin := setupValueRepo(t, pathEnv)
	runIn(t, origin, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	runIn(t, origin, pathEnv, "git", "add", ".")
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-m", "encrypt")

	cloneDir := t.TempDir()
	clone := filepath.Join(cloneDir, "clone")
	runIn(t, cloneDir, pathEnv, "git", "clone", "-q", origin, clone)

	out, err := runInitWith(t, clone, pathEnv, []string{passwordEnv + "=value-mode-password"}, "")
	if err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 file decrypted") {
		t.Errorf("join did not report the decrypted count:\n%s", out)
	}

	got, err := os.ReadFile(filepath.Join(clone, "config", "staging.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), `password: "s3cr3t"`) {
		t.Errorf("value was not decrypted after join:\n%s", got)
	}
}
