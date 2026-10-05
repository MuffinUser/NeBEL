// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const dotenvLocal = `# Local overrides
APP_NAME=nebel
export DATABASE_PASSWORD="p@ss \"word\""   # rotate quarterly
API_TOKEN=tok_live
`

const appProperties = `# Application settings
database.url=jdbc:postgresql://db/app
database.password = s3cr3t
api.token:tok_live
`

// setupLineRepo bootstraps a repo containing .env.local and
// config/app.properties.
func setupLineRepo(t *testing.T, pathEnv string) string {
	t.Helper()
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "line-format-password")

	if err := os.MkdirAll(filepath.Join(repo, "config"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{".env.local": dotenvLocal, "config/app.properties": appProperties} {
		if err := os.WriteFile(filepath.Join(repo, filepath.FromSlash(name)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return repo
}

// AC-8.11, AC-6.14: `add field` on .env and .properties files encrypts
// exactly the named keys, keeps quotes and comments, leaves the working
// tree readable, and a fresh clone decrypts it with the password alone.
func TestAddFieldLineFormats(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupLineRepo(t, pathEnv)

	runIn(t, repo, pathEnv, "nebel", "add", "field", ".env.local", "DATABASE_PASSWORD", "API_TOKEN")
	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/app.properties", "database.password")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt line-format fields")

	env := runIn(t, repo, pathEnv, "git", "show", "HEAD:.env.local")
	if strings.Contains(env, "p@ss") || strings.Contains(env, "tok_live") {
		t.Errorf("a named .env value was committed in plaintext:\n%s", env)
	}
	for _, kept := range []string{"APP_NAME=nebel\n", `export DATABASE_PASSWORD="ENC[`, `]"   # rotate quarterly`, "API_TOKEN=ENC["} {
		if !strings.Contains(env, kept) {
			t.Errorf("committed .env lacks %q:\n%s", kept, env)
		}
	}
	props := runIn(t, repo, pathEnv, "git", "show", "HEAD:config/app.properties")
	if strings.Contains(props, "s3cr3t") || !strings.Contains(props, "database.password = ENC[") || !strings.Contains(props, "api.token:tok_live") {
		t.Errorf("committed .properties is wrong:\n%s", props)
	}

	for name, want := range map[string]string{".env.local": dotenvLocal, "config/app.properties": appProperties} {
		onDisk, err := os.ReadFile(filepath.Join(repo, filepath.FromSlash(name)))
		if err != nil {
			t.Fatal(err)
		}
		if string(onDisk) != want {
			t.Errorf("%s changed in the working tree:\n got  = %q\n want = %q", name, onDisk, want)
		}
		if err := os.Remove(filepath.Join(repo, filepath.FromSlash(name))); err != nil {
			t.Fatal(err)
		}
	}
	runIn(t, repo, pathEnv, "git", "checkout", "--", ".")
	if status := runIn(t, repo, pathEnv, "git", "status", "--porcelain"); strings.TrimSpace(status) != "" {
		t.Errorf("checkout left the tree dirty, so clean is not deterministic:\n%s", status)
	}

	cloneDir := t.TempDir()
	clone := filepath.Join(cloneDir, "clone")
	runIn(t, cloneDir, pathEnv, "git", "clone", "-q", repo, clone)
	if out, err := runInitWith(t, clone, pathEnv, []string{passwordEnv + "=line-format-password"}, ""); err != nil {
		t.Fatalf("join: %v\n%s", err, out)
	}
	got, err := os.ReadFile(filepath.Join(clone, ".env.local"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != dotenvLocal {
		t.Errorf("clone did not decrypt .env.local:\n got  = %q\n want = %q", got, dotenvLocal)
	}
}

// AC-8.4, AC-8.11: a duplicated key or a multi-line value is refused when
// the rule is written, and no rule is written.
func TestAddFieldRefusesDuplicateAndMultilineKeys(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupLineRepo(t, pathEnv)
	files := map[string]string{
		".env":           "TOKEN=a\nTOKEN=b\n",
		"app.properties": "key=one \\\n    two\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(repo, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	for name, tt := range map[string]struct{ key, want string }{
		".env":           {"TOKEN", "more than once"},
		"app.properties": {"key", "several lines"},
	} {
		out, err := runInExpectingError(t, repo, pathEnv, "nebel", "add", "field", name, tt.key)
		if err == nil {
			t.Errorf("add field %s %s: want an error, got:\n%s", name, tt.key, out)
		}
		if !strings.Contains(out, tt.want) {
			t.Errorf("add field %s %s: error does not explain itself:\n%s", name, tt.key, out)
		}
	}
	if config := readConfig(t, repo); strings.Contains(config, "app.properties") || strings.Contains(config, "files: .env\n") {
		t.Errorf("a refused key still wrote a rule:\n%s", config)
	}
}

// Spec 11 on a line format: rotate re-encrypts a .env field onto the new
// version without touching the rest of the file.
func TestRotateReencryptsDotenvFields(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupLineRepo(t, pathEnv)

	runIn(t, repo, pathEnv, "nebel", "add", "field", ".env.local", "DATABASE_PASSWORD")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt")

	if out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password"}, ""); err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	staged := runIn(t, repo, pathEnv, "git", "show", ":.env.local")
	if !strings.Contains(staged, `DATABASE_PASSWORD="ENC[AES256_SIV_TB,key:2,`) || strings.Contains(staged, "key:1,") {
		t.Errorf("staged .env field is not on version 2 only:\n%s", staged)
	}
	if !strings.Contains(staged, "API_TOKEN=tok_live\n") {
		t.Errorf("unrelated content did not survive rotation:\n%s", staged)
	}
}
