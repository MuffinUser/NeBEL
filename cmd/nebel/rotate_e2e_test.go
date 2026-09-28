// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
)

// runRotateWith runs `nebel rotate ...` in dir, with extraEnv added to the
// environment and stdin as the process's standard input — mirrors
// runInitWith for the one other command that takes a password.
func runRotateWith(t *testing.T, dir, pathEnv string, extraEnv []string, stdin string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(filepath.Join(binDir, binName), append([]string{"rotate"}, args...)...)
	cmd.Dir = dir
	cmd.Env = append(append(os.Environ(), "PATH="+pathEnv), extraEnv...)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func readConfig(t *testing.T, repo string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(repo, config.FileName))
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// AC-11.1: rotate on a clone with no local key at all fails, naming
// `nebel init`, and does not touch the committed config.
func TestRotateRequiresLocalKey(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")
	clone := cloneOf(t, pathEnv, origin)

	before := readConfig(t, clone)

	out, err := runInExpectingError(t, clone, pathEnv, "nebel", "rotate")
	if err == nil {
		t.Fatalf("rotate with no local key: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "nebel init") {
		t.Errorf("error does not name `nebel init`:\n%s", out)
	}

	if after := readConfig(t, clone); before != after {
		t.Error("a failed rotate modified the committed config")
	}
}

// AC-11.2 / AC-11.9: rotate bumps key_version, replaces salt and canary,
// leaves rules untouched, and is not idempotent — a second run mints a
// third, independent version rather than converging on an "already
// rotated" state.
func TestRotateBumpsVersionAndIsNotIdempotent(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")

	before := readConfig(t, origin)

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password-1"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	afterFirst := readConfig(t, origin)
	if afterFirst == before {
		t.Fatal("rotate did not change the committed config")
	}
	if !strings.Contains(afterFirst, "key_version: 2") {
		t.Errorf("config after first rotate does not report version 2:\n%s", afterFirst)
	}
	if !strings.Contains(afterFirst, "secrets/*.pem") {
		t.Errorf("rotate changed the rules:\n%s", afterFirst)
	}
	if !strings.Contains(out, "version 2") {
		t.Errorf("rotate output does not name the new version:\n%s", out)
	}

	out, err = runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password-2"}, "")
	if err != nil {
		t.Fatalf("second nebel rotate: %v\n%s", err, out)
	}
	afterSecond := readConfig(t, origin)
	if !strings.Contains(afterSecond, "key_version: 3") {
		t.Errorf("config after second rotate does not report version 3:\n%s", afterSecond)
	}
	if !strings.Contains(out, "version 3") {
		t.Errorf("second rotate output does not name version 3:\n%s", out)
	}
}

// AC-11.3: a generated password is printed exactly once, and a positional
// password argument is refused (rotate never prompts interactively).
func TestRotateGeneratesPasswordByDefault(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")

	out, err := runRotateWith(t, origin, pathEnv, nil, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Generated new password:") {
		t.Errorf("no generated password reported:\n%s", out)
	}
}

func TestRotateRejectsPasswordArgument(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")
	before := readConfig(t, origin)

	out, err := runRotateWith(t, origin, pathEnv, nil, "", "some-password")
	if err == nil {
		t.Fatalf("rotate with a password argument: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "process list") {
		t.Errorf("error does not explain the exposure:\n%s", out)
	}
	if after := readConfig(t, origin); before != after {
		t.Error("a refused rotate modified the committed config")
	}
}

// AC-11.4 (revised — see rotate.go's package doc): rotate eagerly
// re-encrypts every already-decrypted managed file under the version it
// just minted, so the committed blob changes and the new tag names the
// new version, while the working tree's plaintext is untouched — only the
// ciphertext wrapping it changes.
func TestRotateReencryptsExistingContent(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "origin-password")

	blobBefore := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}

	staged := runIn(t, origin, pathEnv, "git", "diff", "--cached", "--name-only")
	if !strings.Contains(staged, "secrets/prod.pem") {
		t.Errorf("rotate did not stage the existing file for re-encryption:\n%s", staged)
	}

	stagedBlob := runIn(t, origin, pathEnv, "git", "show", ":secrets/prod.pem")
	if stagedBlob == blobBefore {
		t.Error("rotate left the staged ciphertext byte-for-byte identical to what was committed")
	}
	if !strings.Contains(stagedBlob, "key:2,") {
		t.Errorf("staged blob is not tagged version 2:\n%s", stagedBlob)
	}

	onDisk, err := os.ReadFile(filepath.Join(origin, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != plaintext {
		t.Errorf("working tree content changed across rotation: got %q, want %q", onDisk, plaintext)
	}
}

// AC-11.5: the machine that rotated keeps reading everything it could read
// before — the old key is still registered, so old content and the old
// canary both keep verifying.
func TestRotateKeepsOldKeyRegistered(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "origin-password")

	keyV1Before := runIn(t, origin, pathEnv, "git", "config", "--local", "--get", "filter.nebel.key")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}

	keyV1After := runIn(t, origin, pathEnv, "git", "config", "--local", "--get", "filter.nebel.key")
	if keyV1Before != keyV1After {
		t.Error("rotate disturbed the existing version's registered key")
	}
	if _, err := runInExpectingError(t, origin, pathEnv, "git", "config", "--local", "--get", "filter.nebel.key2"); err != nil {
		t.Errorf("rotate did not register the new version's key: %v", err)
	}

	// The pre-rotation content, still tagged version 1, must still decrypt.
	onDisk, err := os.ReadFile(filepath.Join(origin, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != plaintext {
		t.Errorf("after rotate, pre-existing file = %q, want still-decrypted %q", onDisk, plaintext)
	}
}

// AC-11.6 (revised): rotate stages the config plus every managed file it
// actually re-encrypted — here, the one existing secret — and nothing
// else.
func TestRotateStagesConfigAndMigratedContent(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}

	staged := strings.Fields(runIn(t, origin, pathEnv, "git", "diff", "--cached", "--name-only"))
	sort.Strings(staged)
	want := []string{config.FileName, "secrets/prod.pem"}
	if strings.Join(staged, ",") != strings.Join(want, ",") {
		t.Errorf("staged files after rotate = %v, want %v", staged, want)
	}
}

// AC-11.10 (revised): rotate now performs the renormalize itself, so
// running `git add --renormalize` again right after is a no-op — the
// content is already converged onto the version rotate just minted.
func TestRenormalizeAfterRotateIsANoOp(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "origin-password")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-am", "rotate encryption key")

	blobBefore := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem")
	runIn(t, origin, pathEnv, "git", "add", "--renormalize", "--", "secrets/prod.pem")

	staged := strings.TrimSpace(runIn(t, origin, pathEnv, "git", "diff", "--cached", "--name-only"))
	if staged != "" {
		t.Errorf("renormalize after rotate re-staged already-converged content: %q", staged)
	}
	if got := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem"); got != blobBefore {
		t.Errorf("renormalize after rotate changed the committed blob:\n before = %s\n after  = %s", blobBefore, got)
	}

	onDisk, err := os.ReadFile(filepath.Join(origin, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != plaintext {
		t.Errorf("working tree content changed: got %q, want %q", onDisk, plaintext)
	}
}

// The bug this guards against: rotate must never mint a new version while
// silently leaving part of the repo permanently stuck on an old one.
// Eager re-encryption only ever converges content this clone can
// currently decrypt (checkFullyDecryptable in rotate.go); a clone missing
// an older key version must be refused, with the config left untouched,
// rather than "succeeding" with a `migrated` count that came up short.
func TestRotateRefusesWhenContentUndecryptable(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")
	v1Blob := runIn(t, origin, pathEnv, "git", "show", "HEAD:secrets/prod.pem")

	// v1 -> v2: this clone holds v1's key, so the existing secret
	// converges cleanly (TestRotateReencryptsExistingContent covers this
	// path in detail) — an ordinary, correctly behaving rotation.
	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password-2"}, "")
	if err != nil {
		t.Fatalf("nebel rotate (v1 -> v2): %v\n%s", err, out)
	}
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-am", "rotate to v2")

	// Simulate the one way a repo still ends up with config at v2 but a
	// file tagged v1 despite that: a commit made outside nebel entirely —
	// a stray manual edit, a bad merge, a repo carried over from before
	// this refusal existed. `-c filter.nebel.clean=cat` bypasses clean for
	// this one commit so it actually sticks, the same trick
	// migration_e2e_test.go uses to simulate a foreign commit.
	secretPath := filepath.Join(origin, "secrets", "prod.pem")
	if err := os.WriteFile(secretPath, []byte(v1Blob), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, origin, pathEnv, "git", "-c", "filter.nebel.clean=cat", "add", "--", "secrets/prod.pem")
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-m", "simulate a stray v1 blob landing after rotation")

	// A fresh clone joins at v2 only — it never registers v1's key, so
	// `nebel init` there leaves secrets/prod.pem (tagged v1) as ciphertext
	// passthrough, the same state TestCloneWithoutInitStaysEncrypted
	// checks for a never-rotated clone.
	clone := cloneOf(t, pathEnv, origin)
	if _, err := runInitWith(t, clone, pathEnv, []string{passwordEnv + "=rotated-password-2"}, ""); err != nil {
		t.Fatalf("nebel init (clone, v2 only): %v", err)
	}
	if onDisk, err := os.ReadFile(filepath.Join(clone, "secrets", "prod.pem")); err != nil || !strings.Contains(string(onDisk), "key:1,") {
		t.Fatalf("test setup did not leave secrets/prod.pem undecryptable in the clone: %q, err=%v", onDisk, err)
	}
	before := readConfig(t, clone)

	out, err = runRotateWith(t, clone, pathEnv, []string{passwordEnv + "=rotated-password-3"}, "")
	if err == nil {
		t.Fatalf("rotate with an undecryptable managed file: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "secrets/prod.pem") {
		t.Errorf("error does not name the stuck file:\n%s", out)
	}
	if !strings.Contains(out, "version 1") {
		t.Errorf("error does not name the version it's stuck on:\n%s", out)
	}
	if !strings.Contains(out, "nebel init --version") {
		t.Errorf("error does not point at the fix:\n%s", out)
	}
	if after := readConfig(t, clone); before != after {
		t.Error("a refused rotate modified the committed config")
	}
}

// --password-stdin lets the new password be piped straight from a secret
// store, mirroring init's AC-7.11.
func TestRotateTakesPasswordFromStdin(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "origin-password")

	out, err := runRotateWith(t, origin, pathEnv, nil, "stdin-rotated-password\n", "--password-stdin")
	if err != nil {
		t.Fatalf("nebel rotate --password-stdin: %v\n%s", err, out)
	}
	if !strings.Contains(readConfig(t, origin), "key_version: 2") {
		t.Errorf("config after rotate via stdin does not report version 2:\n%s", readConfig(t, origin))
	}
}

// Rotating to the same password as the one currently registered is
// refused: the version and salt would still change, but silently
// defeats the point of rotating if $NEBEL_PASSWORD was left unchanged.
func TestRotateRejectsSamePassword(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, _ := setupEncryptedOrigin(t, pathEnv, "same-password")
	before := readConfig(t, origin)

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=same-password"}, "")
	if err == nil {
		t.Fatalf("rotate with the unchanged password: want an error, got success:\n%s", out)
	}
	if after := readConfig(t, origin); before != after {
		t.Error("a refused rotate (same password) modified the committed config")
	}
}

// The mode: value counterpart of TestRotateRefusesWhenContentUndecryptable:
// checkFullyDecryptable's field-level branch (Locate + IsEncrypted on the
// span, not the whole file) must catch a stuck per-value secret the same
// way it catches a stuck whole file.
func TestRotateRefusesWhenValueModeFieldUndecryptable(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)
	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt database.password")
	v1Blob := runIn(t, repo, pathEnv, "git", "show", "HEAD:config/staging.yaml")

	out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password-2"}, "")
	if err != nil {
		t.Fatalf("nebel rotate (v1 -> v2): %v\n%s", err, out)
	}
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-am", "rotate to v2")

	// Simulate a stray v1-tagged commit landing after the fact, same
	// trick as TestRotateRefusesWhenContentUndecryptable.
	yamlPath := filepath.Join(repo, "config", "staging.yaml")
	if err := os.WriteFile(yamlPath, []byte(v1Blob), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, repo, pathEnv, "git", "-c", "filter.nebel.clean=cat", "add", "--", "config/staging.yaml")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "simulate a stray v1 field landing after rotation")

	clone := cloneOf(t, pathEnv, repo)
	if _, err := runInitWith(t, clone, pathEnv, []string{passwordEnv + "=rotated-password-2"}, ""); err != nil {
		t.Fatalf("nebel init (clone, v2 only): %v", err)
	}
	if onDisk, err := os.ReadFile(filepath.Join(clone, "config", "staging.yaml")); err != nil || !strings.Contains(string(onDisk), "key:1,") {
		t.Fatalf("test setup did not leave the field undecryptable in the clone: %q, err=%v", onDisk, err)
	}
	before := readConfig(t, clone)

	out, err = runRotateWith(t, clone, pathEnv, []string{passwordEnv + "=rotated-password-3"}, "")
	if err == nil {
		t.Fatalf("rotate with an undecryptable field: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "config/staging.yaml") || !strings.Contains(out, "database.password") {
		t.Errorf("error does not name the stuck file and field:\n%s", out)
	}
	if !strings.Contains(out, "version 1") {
		t.Errorf("error does not name the version it's stuck on:\n%s", out)
	}
	if after := readConfig(t, clone); before != after {
		t.Error("a refused rotate modified the committed config")
	}
}

// The mode: value counterpart of TestRotateReencryptsExistingContent:
// rotate re-encrypts a per-field secret the same way it does a whole
// file, retagging just the configured field under the new version and
// leaving the rest of the document (and any unencrypted sibling fields)
// alone.
func TestRotateReencryptsValueModeFields(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupValueRepo(t, pathEnv)

	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt database.password")

	blobBefore := runIn(t, repo, pathEnv, "git", "show", "HEAD:config/staging.yaml")
	if !strings.Contains(blobBefore, "key:1,") {
		t.Fatalf("test setup did not commit the field tagged version 1:\n%s", blobBefore)
	}

	out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}

	staged := runIn(t, repo, pathEnv, "git", "diff", "--cached", "--name-only")
	if !strings.Contains(staged, "config/staging.yaml") {
		t.Errorf("rotate did not stage the value-mode file for re-encryption:\n%s", staged)
	}

	stagedBlob := runIn(t, repo, pathEnv, "git", "show", ":config/staging.yaml")
	if !strings.Contains(stagedBlob, "key:2,") {
		t.Errorf("staged field is not tagged version 2:\n%s", stagedBlob)
	}
	if strings.Contains(stagedBlob, "key:1,") {
		t.Errorf("staged blob still carries a version 1 tag:\n%s", stagedBlob)
	}
	for _, kept := range []string{"host: db.internal      # not a secret", "port: 5432", "alpha", "beta"} {
		if !strings.Contains(stagedBlob, kept) {
			t.Errorf("unrelated content %q did not survive rotation:\n%s", kept, stagedBlob)
		}
	}

	onDisk, err := os.ReadFile(filepath.Join(repo, "config", "staging.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != stagingYAML {
		t.Errorf("working tree content changed across rotation:\n got  = %q\n want = %q", onDisk, stagingYAML)
	}
}

// A direct check of the user-facing guarantee eager re-encryption exists
// for: a fresh clone that never saw the pre-rotation password gets
// everything decrypted from just the new one — no per-file "needs key
// version 1" leftovers, because nothing committed still carries that tag.
func TestFreshCloneAfterRotateDecryptsEverythingWithNewPasswordAlone(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "origin-password")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-am", "rotate encryption key")

	clone := cloneOf(t, pathEnv, origin)
	out, err = runInitWith(t, clone, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel init (fresh clone, new password only): %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 file decrypted locally") {
		t.Errorf("fresh clone did not report everything decrypted with just the new password:\n%s", out)
	}
	if strings.Contains(out, "could not be") {
		t.Errorf("fresh clone left something undecryptable despite rotate's guarantee:\n%s", out)
	}

	got, err := os.ReadFile(filepath.Join(clone, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plaintext {
		t.Errorf("fresh clone content = %q, want decrypted %q", got, plaintext)
	}
}

// Eager re-encryption's cost: since rotate now changes the committed
// ciphertext of existing files (not just .nebel.yaml), an existing
// clone's next `git pull` needs to smudge the changed blob with a key it
// doesn't have yet. Rather than aborting the whole git operation (spec 06
// AC-6.11's old behavior), smudge passes the ciphertext through and warns
// (filterop.Skipped) — so the pull itself succeeds, leaving that file
// exactly as "clean" as a brand-new clone would see it before its first
// `nebel init`: still encrypted, `git status` reporting nothing locally
// modified. `nebel init` with the new password then decrypts it in place,
// same as any other join.
func TestExistingCloneRecoversAfterRotateWithPlainPull(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "origin-password")
	clone := cloneOf(t, pathEnv, origin)
	initWithPassword(t, clone, pathEnv, "origin-password")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-am", "rotate encryption key")

	// A plain pull succeeds — no recovery dance needed — and warns on
	// stderr about the field it couldn't reach rather than erroring.
	pullOut := runIn(t, clone, pathEnv, "git", "pull")
	if !strings.Contains(pullOut, "secrets/prod.pem") || !strings.Contains(pullOut, "needs key version 2") {
		t.Errorf("pull did not warn about the field it left encrypted:\n%s", pullOut)
	}
	if !strings.Contains(pullOut, "Fast-forward") {
		t.Errorf("pull did not fast-forward cleanly:\n%s", pullOut)
	}

	stillEncrypted, err := os.ReadFile(filepath.Join(clone, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(stillEncrypted), "ENC[") {
		t.Fatalf("after the pull, secrets/prod.pem = %q, want it left as ciphertext", stillEncrypted)
	}
	if status := strings.TrimSpace(runIn(t, clone, pathEnv, "git", "status", "--porcelain")); status != "" {
		t.Errorf("pull left the working tree looking locally modified:\n%s", status)
	}

	// A forced renormalize (the "is this really clean" check): with
	// nothing decryptable yet, clean has nothing new to encrypt (the
	// field is already tagged) and so needs no key at all — it must not
	// error, and must stage nothing.
	runIn(t, clone, pathEnv, "git", "add", "--renormalize", "--", ".")
	if staged := strings.TrimSpace(runIn(t, clone, pathEnv, "git", "diff", "--cached", "--name-only")); staged != "" {
		t.Errorf("renormalize on undecryptable content staged something: %q", staged)
	}

	// `nebel init` with the new password decrypts in place, exactly like
	// joining a repo for the first time.
	out, err = runInitWith(t, clone, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel init (new password): %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 file decrypted locally") {
		t.Errorf("init did not report the field decrypted:\n%s", out)
	}

	got, err := os.ReadFile(filepath.Join(clone, "secrets", "prod.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != plaintext {
		t.Errorf("after init, content = %q, want decrypted %q", got, plaintext)
	}
	if status := strings.TrimSpace(runIn(t, clone, pathEnv, "git", "status", "--porcelain")); status != "" {
		t.Errorf("init left the working tree dirty:\n%s", status)
	}
}

// The mode: value counterpart of
// TestExistingCloneRecoversAfterRotateWithPlainPull: the same graceful
// pull, and forced-renormalize-is-a-no-op check, for a per-field secret —
// this is what actually exercises cleanValues's haveKey gate (Clean must
// not demand the current version's key just to leave an already-tagged
// field alone), as opposed to the whole-file path Clean takes for
// secrets/prod.pem.
func TestExistingCloneRecoversAfterRotateWithPlainPullValueMode(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin := setupValueRepo(t, pathEnv)
	runIn(t, origin, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	runIn(t, origin, pathEnv, "git", "add", ".")
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-m", "encrypt database.password")

	clone := cloneOf(t, pathEnv, origin)
	initWithPassword(t, clone, pathEnv, "value-mode-password")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	runIn(t, origin, pathEnv, "git", "commit", "-q", "-am", "rotate encryption key")

	pullOut := runIn(t, clone, pathEnv, "git", "pull")
	if !strings.Contains(pullOut, "config/staging.yaml") || !strings.Contains(pullOut, "database.password") || !strings.Contains(pullOut, "needs key version 2") {
		t.Errorf("pull did not warn about the field it left encrypted:\n%s", pullOut)
	}
	if !strings.Contains(pullOut, "Fast-forward") {
		t.Errorf("pull did not fast-forward cleanly:\n%s", pullOut)
	}

	stagedYAML, err := os.ReadFile(filepath.Join(clone, "config", "staging.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(stagedYAML), `password: "ENC[`) {
		t.Fatalf("after the pull, database.password was not left as ciphertext:\n%s", stagedYAML)
	}
	if status := strings.TrimSpace(runIn(t, clone, pathEnv, "git", "status", "--porcelain")); status != "" {
		t.Errorf("pull left the working tree looking locally modified:\n%s", status)
	}

	runIn(t, clone, pathEnv, "git", "add", "--renormalize", "--", ".")
	if staged := strings.TrimSpace(runIn(t, clone, pathEnv, "git", "diff", "--cached", "--name-only")); staged != "" {
		t.Errorf("renormalize on undecryptable content staged something: %q", staged)
	}

	out, err = runInitWith(t, clone, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel init (new password): %v\n%s", err, out)
	}
	if !strings.Contains(out, "1 file decrypted locally") {
		t.Errorf("init did not report the field decrypted:\n%s", out)
	}

	got, err := os.ReadFile(filepath.Join(clone, "config", "staging.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(got), "ENC[") {
		t.Errorf("after init, content still encrypted:\n%s", got)
	}
	if !strings.Contains(string(got), `password: "s3cr3t"`) {
		t.Errorf("after init, database.password was not decrypted back to its original value:\n%s", got)
	}
	if status := strings.TrimSpace(runIn(t, clone, pathEnv, "git", "status", "--porcelain")); status != "" {
		t.Errorf("init left the working tree dirty:\n%s", status)
	}
}

// AC-11.8: rotate's output never includes decrypted plaintext.
func TestRotateOutputHasNoSecrets(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	origin, plaintext := setupEncryptedOrigin(t, pathEnv, "origin-password")

	out, err := runRotateWith(t, origin, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err != nil {
		t.Fatalf("nebel rotate: %v\n%s", err, out)
	}
	if strings.Contains(out, plaintext) {
		t.Errorf("rotate output leaked decrypted plaintext:\n%s", out)
	}
}
