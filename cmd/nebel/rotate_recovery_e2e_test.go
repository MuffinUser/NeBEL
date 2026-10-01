// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/MuffinUser/nebel/internal/config"
)

// setupRotatableValueRepo bootstraps a repo with one mode: value field
// already encrypted and committed under key version 1 — a minimal
// starting point for forcing a failure partway through a later rotate.
func setupRotatableValueRepo(t *testing.T, pathEnv string) string {
	t.Helper()
	repo := setupValueRepo(t, pathEnv)
	runIn(t, repo, pathEnv, "nebel", "add", "field", "config/staging.yaml", "database.password")
	runIn(t, repo, pathEnv, "git", "add", ".")
	runIn(t, repo, pathEnv, "git", "commit", "-q", "-m", "encrypt database.password")
	return repo
}

// breakStagingPassword overwrites config/staging.yaml's database.password
// value, in the working tree only, with one containing a raw control
// character — the same value TestCleanValuesRejectsUnrenderableControlCharacter
// (internal/filterop) proves Clean refuses, via format.ErrControlCharacterUnsupported.
// Used here as a fault seam: checkFullyDecryptable doesn't flag it (it
// isn't an ENC[...] tag), so rotate proceeds past its own pre-flight
// check and fails only once gitutil.RenormalizeAll actually tries to
// re-encrypt it.
func breakStagingPassword(t *testing.T, repo string) {
	t.Helper()
	path := filepath.Join(repo, "config", "staging.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(data), `password: "s3cr3t"`, "password: \"a\x01b\"", 1)
	if broken == string(data) {
		t.Fatal("test setup: database.password literal not found to break")
	}
	if err := os.WriteFile(path, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Regression test for the 2026-09-30 reanalysis's finding 4.1: the
// previous rotateRecoveryHint claimed `git checkout -- .` "fully
// discards" a failed rotation, but that command restores the working
// tree from the index, not HEAD — once gitutil.Add has already staged
// the rotated config (exactly the state at the point RenormalizeAll can
// fail), the rotation stayed staged afterward. rotate now reverts
// config.FileName itself instead of telling the user to run a command.
func TestRotateAutomaticallyRevertsOnRenormalizeFailure(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupRotatableValueRepo(t, pathEnv)

	beforeConfig := readConfig(t, repo)
	beforeStagingCommitted := runIn(t, repo, pathEnv, "git", "show", "HEAD:config/staging.yaml")

	breakStagingPassword(t, repo)

	out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err == nil {
		t.Fatalf("rotate with an unrenderable field: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "automatically reverted") {
		t.Errorf("rotate error does not confirm an automatic revert:\n%s", out)
	}
	if strings.Contains(out, "git checkout") || strings.Contains(out, "git reset") {
		t.Errorf("rotate error still tells the user to run a git command by hand:\n%s", out)
	}

	afterConfig := readConfig(t, repo)
	if afterConfig != beforeConfig {
		t.Errorf("config.FileName not fully reverted:\n got  = %q\n want = %q", afterConfig, beforeConfig)
	}

	staged := strings.TrimSpace(runIn(t, repo, pathEnv, "git", "diff", "--cached", "--name-only"))
	if staged != "" {
		t.Errorf("something is still staged after the automatic revert: %q", staged)
	}

	afterStagingCommitted := runIn(t, repo, pathEnv, "git", "show", "HEAD:config/staging.yaml")
	if afterStagingCommitted != beforeStagingCommitted {
		t.Error("the managed file's committed content changed even though rotate never staged it")
	}

	if _, ok := registeredKeyValue(t, repo, pathEnv, 2); ok {
		t.Error("version 2's orphaned local key was not removed by the automatic revert (audit 2026-09-30, reanalysis 4.3: a teammate's later, independent rotation to the same version number would collide with it)")
	}
}

// Companion to the above: a second `nebel rotate` run before the first
// one is committed (AC-11.9 explicitly allows this) must, on its own
// failure, revert to the still-staged result of the *first* rotation —
// not to HEAD, which is one rotation further back. An earlier draft of
// this fix restored from HEAD unconditionally and would have silently
// discarded the first rotation's legitimate staged work here.
func TestRotateRevertsToPriorStagedRotationNotHEAD(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupRotatableValueRepo(t, pathEnv)

	out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password-1"}, "")
	if err != nil {
		t.Fatalf("first nebel rotate: %v\n%s", err, out)
	}
	stagedAfterFirstRotate := readConfig(t, repo)
	if !strings.Contains(stagedAfterFirstRotate, "key_version: 2") {
		t.Fatalf("test setup: first rotate did not reach version 2:\n%s", stagedAfterFirstRotate)
	}
	stagedPathsAfterFirstRotate := strings.TrimSpace(runIn(t, repo, pathEnv, "git", "diff", "--cached", "--name-only"))

	// An edit made after the first rotate, still unstaged — plausible if
	// someone touched the file before running rotate again.
	breakStagingPassword(t, repo)

	out, err = runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password-2"}, "")
	if err == nil {
		t.Fatalf("second rotate with an unrenderable field: want an error, got success:\n%s", out)
	}

	afterFailedSecondRotate := readConfig(t, repo)
	if afterFailedSecondRotate != stagedAfterFirstRotate {
		t.Errorf("second rotate's failure did not revert to the first rotate's staged result:\n got  = %q\n want = %q", afterFailedSecondRotate, stagedAfterFirstRotate)
	}
	if strings.Contains(afterFailedSecondRotate, "key_version: 1") {
		t.Error("second rotate's failure reverted all the way back to the pre-rotation HEAD, discarding the first rotation's legitimate staged work")
	}

	staged := strings.TrimSpace(runIn(t, repo, pathEnv, "git", "diff", "--cached", "--name-only"))
	if staged != stagedPathsAfterFirstRotate {
		t.Errorf("staged files after the failed second rotate = %q, want unchanged from after the first rotate %q", staged, stagedPathsAfterFirstRotate)
	}
}

// A generated password is shown before any state changes (audit
// 2026-09-30, R03) — but once a later failure auto-reverts the attempt
// that generated it, that password no longer applies to anything. The
// error must say so, rather than leaving the earlier "store it now"
// notice as the last word on it.
func TestRotateFailureDiscardsGeneratedPasswordAfterSuccessfulRevert(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupRotatableValueRepo(t, pathEnv)

	beforeConfig := readConfig(t, repo)
	breakStagingPassword(t, repo)

	// No password supplied: rotate generates and prints one before it
	// fails, exactly the sequence that makes the "discard it" note matter.
	out, err := runRotateWith(t, repo, pathEnv, nil, "")
	if err == nil {
		t.Fatalf("rotate with an unrenderable field: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "Generated new password:") {
		t.Fatalf("test setup: rotate did not generate a password:\n%s", out)
	}
	if !strings.Contains(out, "discard it") {
		t.Errorf("rotate error does not tell the user to discard the now-unused generated password:\n%s", out)
	}

	if afterConfig := readConfig(t, repo); afterConfig != beforeConfig {
		t.Errorf("config.FileName not fully reverted:\n got  = %q\n want = %q", afterConfig, beforeConfig)
	}
}

// Regression test for a gap in the first version of this fix's revert
// logic: it re-staged config.FileName unconditionally after restoring it,
// which would have swept up any pre-existing *unstaged* edit to it (made
// before this rotate attempt even started) into the index — something
// this attempt never did and has no business doing. Re-staging must only
// happen when this attempt's own gitutil.Add already staged config.FileName
// (the RenormalizeAll failure point) — not when gitutil.Add itself is what
// failed, forced here via a stale .git/index.lock.
func TestRotateFailureDoesNotStageUnrelatedPreexistingConfigEdit(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupRotatableValueRepo(t, pathEnv)

	// An edit to .nebel.yaml that predates this rotate attempt and was
	// never staged — config.Load/Save round-trips it into whatever rotate
	// saves, so it must survive untouched in both the working tree (with
	// the edit) and the index (without it) if this attempt fails.
	configPath := filepath.Join(repo, config.FileName)
	before, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	preexistingEdit := strings.Replace(string(before), "rules:\n", "rules:\n- files: \"*.unrelated\"\n  mode: file\n", 1)
	if preexistingEdit == string(before) {
		t.Fatal("test setup: rules literal not found to extend")
	}
	if err := os.WriteFile(configPath, []byte(preexistingEdit), 0o644); err != nil {
		t.Fatal(err)
	}
	indexBefore := runIn(t, repo, pathEnv, "git", "show", ":"+config.FileName)

	lockPath := filepath.Join(repo, ".git", "index.lock")
	if err := os.WriteFile(lockPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Remove(lockPath) })

	out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err == nil {
		t.Fatalf("rotate with a stale index.lock: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "automatically reverted") {
		t.Errorf("rotate error does not confirm an automatic revert:\n%s", out)
	}

	afterWorktree, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterWorktree) != preexistingEdit {
		t.Errorf("the pre-existing unstaged edit was not preserved in the working tree:\n got  = %q\n want = %q", afterWorktree, preexistingEdit)
	}

	os.Remove(lockPath) // `git show :path` below needs the index usable again
	indexAfter := runIn(t, repo, pathEnv, "git", "show", ":"+config.FileName)
	if indexAfter != indexBefore {
		t.Errorf("the pre-existing unstaged edit was swept into the index by the failed rotate's revert:\n got  = %q\n want = %q", indexAfter, indexBefore)
	}
}

// Regression test for the second part of the 2026-09-30 reanalysis's
// finding 4.3: two concurrent `nebel rotate` processes in the same clone
// used to be able to both read key_version: 1 and each independently
// mint version 2 with a different key — Set's own lost-update fix only
// decided which of the two keys silently won, not whether both proceeded
// at all. localkey.LockRotation (acquired by runRotate) now serializes
// the two attempts, so the second one mints version 3 instead of also
// minting version 2.
//
// Subprocess output/errors are collected into slices rather than
// t.Fatal'd from inside the goroutines, since testing.T methods other
// than Log/Logf are not safe to call from a non-test goroutine.
func TestConcurrentRotatesDoNotCollideOnTheSameVersion(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupRotatableValueRepo(t, pathEnv)

	passwords := []string{"rotated-password-a", "rotated-password-b"}
	outs := make([]string, len(passwords))
	errs := make([]error, len(passwords))

	var wg sync.WaitGroup
	for i, pw := range passwords {
		wg.Add(1)
		go func(i int, pw string) {
			defer wg.Done()
			cmd := exec.Command(filepath.Join(binDir, binName), "rotate")
			cmd.Dir = repo
			cmd.Env = append(os.Environ(), "PATH="+pathEnv, passwordEnv+"="+pw)
			out, err := cmd.CombinedOutput()
			outs[i], errs[i] = string(out), err
		}(i, pw)
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent rotate #%d failed: %v\n%s", i, err, outs[i])
		}
	}

	finalConfig := readConfig(t, repo)
	if !strings.Contains(finalConfig, "key_version: 3") {
		t.Errorf("two concurrent rotates did not both proceed to a distinct version (want key_version: 3):\n%s", finalConfig)
	}

	for _, v := range []int{1, 2, 3} {
		if _, ok := registeredKeyValue(t, repo, pathEnv, v); !ok {
			t.Errorf("version %d has no registered local key after two concurrent rotates", v)
		}
	}

	// A silent collision (both processes reading key_version: 1 and each
	// minting version 2 with a different key) wouldn't necessarily show up
	// as key_version: 3 above — the losing process's Save could still run
	// last and leave key_version: 2, while the keyring ends up with the
	// *other* process's key for it. A third, sequential rotate's own
	// AC-11.1 canary check — requiring the local key for the *current*
	// version to verify against the *current* canary — catches exactly
	// that mismatch, which a bare version-number check alone could miss.
	out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password-c"}, "")
	if err != nil {
		t.Fatalf("third, sequential rotate: %v\n%s", err, out)
	}
	if finalConfig := readConfig(t, repo); !strings.Contains(finalConfig, "key_version: 4") {
		t.Errorf("third rotate did not reach version 4 (canary/key mismatch from the concurrent pair?):\n%s", finalConfig)
	}
}

// Regression test for a gap in an earlier draft of this fix: at the
// RenormalizeAll failure point (staged == true), the revert used to
// re-run `git add` against whatever the working tree held by then — which
// is correct for the RESTORED content in the common case, but wrong if
// config.FileName also carried its own pre-existing *unstaged* edit from
// before this rotate attempt even started: `git add` would stage that
// edit too, something this attempt never did. Restoring the index via its
// captured mode+sha (gitutil.SetIndexEntry) instead of re-adding fixes
// this, independent of whatever the working tree holds by the time the
// revert runs.
//
// Unlike TestRotateFailureDoesNotStageUnrelatedPreexistingConfigEdit
// (which forces the gitutil.Add failure point, staged == false, where
// nothing ever gets re-staged at all — a stale index.lock prevents any
// index write, so that test cannot distinguish a correct revert from a
// merely absent one), this one forces the RenormalizeAll failure point
// specifically, so a revert that (incorrectly) re-runs `git add` here
// actually has the opportunity to stage the pre-existing edit, and this
// test can tell the difference.
func TestRotateFailureRestoresExactIndexAtRenormalizeFailure(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := setupRotatableValueRepo(t, pathEnv)

	configPath := filepath.Join(repo, config.FileName)
	committed, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	indexBefore := runIn(t, repo, pathEnv, "git", "show", ":"+config.FileName)

	preexistingEdit := strings.Replace(string(committed), "rules:\n", "rules:\n- files: \"*.unrelated\"\n  mode: file\n", 1)
	if preexistingEdit == string(committed) {
		t.Fatal("test setup: rules literal not found to extend")
	}
	if err := os.WriteFile(configPath, []byte(preexistingEdit), 0o644); err != nil {
		t.Fatal(err)
	}

	// Forces the RenormalizeAll failure point (staged == true): rotate's
	// own Add succeeds and stages this attempt's rotated config (which
	// incorporates the pre-existing edit above, since config.Load reads
	// whatever's currently on disk) before RenormalizeAll fails on the
	// broken field.
	breakStagingPassword(t, repo)

	out, err := runRotateWith(t, repo, pathEnv, []string{passwordEnv + "=rotated-password"}, "")
	if err == nil {
		t.Fatalf("rotate with an unrenderable field: want an error, got success:\n%s", out)
	}
	if !strings.Contains(out, "automatically reverted") {
		t.Errorf("rotate error does not confirm an automatic revert:\n%s", out)
	}

	afterWorktree, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterWorktree) != preexistingEdit {
		t.Errorf("the pre-existing unstaged edit was not preserved in the working tree:\n got  = %q\n want = %q", afterWorktree, preexistingEdit)
	}

	indexAfter := runIn(t, repo, pathEnv, "git", "show", ":"+config.FileName)
	if indexAfter != indexBefore {
		t.Errorf("the pre-existing unstaged edit was swept into the index by the failed rotate's revert:\n got  = %q\n want = %q (the original committed content, never staged by this attempt)", indexAfter, indexBefore)
	}
}
