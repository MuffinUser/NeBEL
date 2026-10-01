// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/gitutil"
	"github.com/MuffinUser/nebel/internal/kdf"
	"github.com/MuffinUser/nebel/internal/localkey"
)

const rotateUsage = "usage: nebel rotate [--password-stdin]"

// runRotate implements `nebel rotate` (spec 11): mint a new, current key
// version, then eagerly re-encrypt every managed file/field under it, so
// a single password (the new one) decrypts everything the repo currently
// tracks. Anyone whose local key currently verifies against the repo's
// canary can run this — not only whoever ran `init` first. It refuses
// up front, before touching any state, if this clone can't currently
// decrypt everything it manages — see checkFullyDecryptable.
func runRotate(args []string) error {
	input, err := parsePasswordFlags(args, rotateUsage, ErrRotatePasswordArgument)
	if err != nil {
		return err
	}

	root, err := gitutil.RepoRoot()
	if err != nil {
		return err
	}
	configPath := filepath.Join(root, config.FileName)
	if !config.Exists(configPath) {
		return fmt.Errorf("no %s found — run `nebel init` first", config.FileName)
	}

	// Serializes this entire operation against another concurrent `nebel
	// rotate` in the same clone (audit 2026-09-30, reanalysis 4.3): without
	// it, two runs could both read the same current version below and each
	// mint the same next one with a different key. See LockRotation's doc
	// comment. Acquired before originalConfigBytes is even read, so a
	// concurrent rotate can't change configPath out from under that
	// snapshot between reading it and this one finishing.
	unlockRotation, err := localkey.LockRotation()
	if err != nil {
		return err
	}
	defer unlockRotation()

	// Captured before anything changes, so a failure partway through can
	// restore configPath to exactly this — not necessarily HEAD's content:
	// AC-11.9 lets `rotate` run again before the previous rotation is even
	// committed, in which case this is that still-staged, uncommitted
	// result, and HEAD would be one rotation further back than what a
	// failed retry needs to revert to (audit 2026-09-30, reanalysis 4.1).
	originalConfigBytes, err := os.ReadFile(configPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", config.FileName, err)
	}
	// The index entry alongside it, for the same reason but the index
	// half: restoring it later via SetIndexEntry, rather than re-running
	// Add against whatever the working tree holds by then, is what keeps
	// a revert from staging a pre-existing unstaged edit to configPath
	// that predates this rotate attempt entirely (audit 2026-09-30,
	// reanalysis 4.1).
	originalConfigIndex, haveOriginalConfigIndex, err := gitutil.IndexEntry(root, config.FileName)
	if err != nil {
		return err
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// AC-11.1: rotate requires the local keyring to already hold a key for
	// the current version that verifies against the current canary.
	currentVersion := cfg.CurrentVersion()
	currentKey, ok, err := localkey.Get(currentVersion)
	if err != nil {
		return fmt.Errorf("reading local key: %w", err)
	}
	if !ok {
		return fmt.Errorf("no local key registered for the current key version %d — run `nebel init` first", currentVersion)
	}
	if err := cfg.VerifyCanary(currentKey); err != nil {
		return fmt.Errorf("local key for version %d does not match this repo's canary — run `nebel init`: %w", currentVersion, err)
	}

	// Rotate's whole point is that afterward, one password decrypts
	// everything. The eager re-encryption below can only converge content
	// that is already sitting as plaintext in the working tree — anything
	// still showing as ENC[...] there (this clone never had the key for
	// whatever version produced it) stays ciphertext no matter how many
	// times rotate runs, permanently stranding it on an older version.
	// Refusing here, before anything is changed, is cheaper than finding
	// out from a `migrated` count that came up short.
	if err := checkFullyDecryptable(root, cfg); err != nil {
		return err
	}

	// AC-11.3: same password-source precedence as init, with no
	// interactive prompt fallback — required=false makes resolve()
	// generate a password instead of prompting when no source supplies
	// one.
	password, err := input.resolve(false)
	if err != nil {
		return err
	}
	generated := password == ""
	if generated {
		password = generatePassword()
		// Shown now, before any state changes below can fail: this is the
		// only place this password is ever displayed, so it must survive
		// even if registering the key, saving the config, or re-encrypting
		// fails partway through (audit 2026-09-30, R03 — previously this
		// ran last, so a later failure could strand an already-active
		// derived key with its password never shown at all).
		printGeneratedPasswordNotice(password)
	}

	// A password identical to the current one would still rotate the
	// version and salt (so the derived key bytes differ), but silently
	// defeats the point: if $NEBEL_PASSWORD was left set to the old value
	// and nothing new was actually supplied, this catches it by checking
	// whether the "new" password re-derives the *current* key under the
	// *current* salt.
	oldSalt, err := cfg.SaltBytes()
	if err != nil {
		return err
	}
	reusedKey, err := kdf.Derive(password, oldSalt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}
	if subtle.ConstantTimeCompare(reusedKey, currentKey) == 1 {
		return fmt.Errorf("the new password is the same as the current one — rotation only helps if the password actually changes")
	}

	// AC-11.2: bump the version, fresh salt, new key, new canary — rules
	// unchanged.
	newVersion := currentVersion + 1
	salt := kdf.NewSalt()
	newKey, err := kdf.Derive(password, salt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}
	canary, err := config.NewCanary(newKey, newVersion)
	if err != nil {
		return err
	}

	next := *cfg
	next.KeyVersion = newVersion
	next.Salt = base64.StdEncoding.EncodeToString(salt)
	next.Canary = canary

	if err := next.VerifyCanary(newKey); err != nil {
		return fmt.Errorf("internal error: freshly created canary did not verify: %w", err)
	}

	// Captured so a failed attempt can put the keyring back exactly how it
	// found it (rotateAttempt.failure): newVersion almost never already
	// has a locally-registered key at this point, but if it somehow does
	// (e.g. `nebel init --version N` fetched it out of band before this
	// clone's own rotate happened to mint the same number), Set below
	// would silently overwrite it, and simply deleting it on revert would
	// be just as wrong as leaving this attempt's own key behind.
	prevKey, hadPrevKey, err := localkey.Get(newVersion)
	if err != nil {
		return fmt.Errorf("reading local key: %w", err)
	}

	// AC-11.5: register the new key before saving the config. If the
	// config write below failed after this, this machine would still be
	// able to clean under the new version on retry; the reverse order
	// could leave a saved config this machine can't yet use.
	attempt := rotateAttempt{
		root:              root,
		configPath:        configPath,
		originalBytes:     originalConfigBytes,
		originalIndex:     originalConfigIndex,
		haveOriginalIndex: haveOriginalConfigIndex,
		newVersion:        newVersion,
		prevKey:           prevKey,
		hadPrevKey:        hadPrevKey,
		generated:         generated,
	}
	if err := localkey.Set(newVersion, newKey); err != nil {
		return fmt.Errorf("registering local key: %w", err)
	}
	if err := next.Save(configPath); err != nil {
		return attempt.failure(false, err)
	}

	// Stage the config, then eagerly re-encrypt every managed file/field
	// under the version just minted, so it's never left to be remembered
	// as a manual follow-up (this used to be the documented `git add
	// --renormalize` escape hatch, spec 11 AC-11.10 — rotate now runs it
	// itself). checkFullyDecryptable above guarantees this actually
	// reaches everything: nothing left encrypted going in means nothing
	// comes out still tagged with the old version.
	if err := gitutil.Add(root, config.FileName); err != nil {
		return attempt.failure(false, err)
	}
	migrated, err := gitutil.RenormalizeAll(root)
	if err != nil {
		return attempt.failure(true, fmt.Errorf("re-encrypting existing content under the new version: %w", err))
	}

	printRotateSummary(newVersion, migrated)
	return nil
}

// rotateAttempt carries what a single runRotate call needs to revert
// itself if it fails partway through (audit 2026-09-30, reanalysis 4.1
// and 4.3).
type rotateAttempt struct {
	root, configPath string

	// originalBytes is configPath's exact content the instant runRotate
	// started — not necessarily HEAD's: AC-11.9 lets `rotate` run again
	// before a previous rotation is even committed, in which case this is
	// that still-staged, uncommitted result, and HEAD would be one
	// rotation further back than what a failed retry needs to revert to.
	originalBytes []byte

	// originalIndex is configPath's index entry ("<mode>,<sha>", see
	// gitutil.IndexEntry) at the same instant, restored via
	// gitutil.SetIndexEntry rather than re-running Add so a revert never
	// stages whatever happens to be in the working tree by the time it
	// runs — including a pre-existing unstaged edit to configPath that
	// predates this attempt and was never staged in the first place.
	originalIndex     string
	haveOriginalIndex bool

	newVersion int

	// prevKey/hadPrevKey is whatever localkey.Get(newVersion) returned
	// right before this attempt's own localkey.Set(newVersion, ...) —
	// almost always hadPrevKey == false, since newVersion doesn't exist
	// yet anywhere else. Restoring exactly this (Set it back, or Remove
	// if there was nothing) rather than unconditionally removing
	// newVersion is what keeps a revert from erasing a key some other,
	// unrelated process had already legitimately registered for that
	// same version number.
	prevKey    []byte
	hadPrevKey bool

	generated bool
}

// failure reverts configPath and the local keyring back to what they held
// before this attempt, and reports cause alongside what that revert did.
// staged must be true only when this attempt's own gitutil.Add already
// staged configPath before the failure being reported — i.e. only for the
// gitutil.RenormalizeAll failure point, not next.Save's or gitutil.Add's
// own.
//
// Nothing runRotate does before the point this is called from is ever
// committed, and no managed file's working tree or index state is ever
// touched by any of its three failure points: `git add --renormalize`
// only stages a managed file when it succeeds for every path in that
// single invocation (verified empirically — git aborts the whole index
// update on the first filter failure), so a failure there leaves every
// managed file exactly as it was. Only configPath and the local keyring
// entry for newVersion ever need undoing.
//
// Restoring the keyring matters beyond tidiness: without it, this
// attempt's orphaned key for newVersion stays registered after the
// revert. If the user doesn't retry, and a teammate's own, independent
// rotation later succeeds in minting that same version number with a
// *different* key, this clone's next `git pull` finds a version its
// keyring already claims to have a key for — Smudge's AC-6.11 passthrough
// only applies to a version the keyring doesn't hold at all, so instead of
// the usual graceful "missing key" passthrough, decryption fails outright
// with a hard authentication error (audit 2026-09-30, reanalysis 4.3).
func (a rotateAttempt) failure(staged bool, cause error) error {
	passwordNote := ""
	if a.generated {
		passwordNote = " The password shown above was never applied to anything — discard it; a retry generates a new one."
	}
	if err := os.WriteFile(a.configPath, a.originalBytes, 0o644); err != nil {
		if a.generated {
			passwordNote = fmt.Sprintf(" %s's working tree copy may still hold the new, uncommitted version the password shown above applies to — keep that password until you've confirmed what %[1]s actually contains.", config.FileName)
		}
		return fmt.Errorf("%w\n\nAdditionally, restoring %s to what it held before this attempt failed: %v.%s Rewrite it by hand before retrying.",
			cause, config.FileName, err, passwordNote)
	}
	if staged {
		if !a.haveOriginalIndex {
			return fmt.Errorf("%w\n\n%s's working tree copy was restored, but it was not tracked in the index before this "+
				"attempt started, so the now-stale staged version can't be restored automatically — run `git rm --cached -- %s` "+
				"by hand before retrying.%s", cause, config.FileName, config.FileName, passwordNote)
		}
		if err := gitutil.SetIndexEntry(a.root, a.originalIndex, config.FileName); err != nil {
			return fmt.Errorf("%w\n\n%s's working tree copy was restored, but re-staging its prior version failed: %v — "+
				"run `git add -- %s` by hand before retrying, so the index doesn't still hold the new version (this may "+
				"also re-stage any of your own unrelated pending edit to it).%s",
				cause, config.FileName, err, config.FileName, passwordNote)
		}
	}
	if a.hadPrevKey {
		if err := localkey.Set(a.newVersion, a.prevKey); err != nil {
			return fmt.Errorf("%w\n\n%s was fully reverted, but restoring version %d's previous local key failed: %v — "+
				"run `nebel init --version %d` again by hand before retrying.%s",
				cause, config.FileName, a.newVersion, err, a.newVersion, passwordNote)
		}
	} else if err := localkey.Remove(a.newVersion); err != nil {
		return fmt.Errorf("%w\n\n%s was fully reverted, but removing the orphaned local key this attempt registered "+
			"for version %d failed: %v — if a teammate's own rotation later mints that same version with a different "+
			"key, this clone's next `git pull` will hard-fail on it instead of the usual graceful passthrough, until "+
			"that stale entry is removed by hand.%s", cause, config.FileName, a.newVersion, err, passwordNote)
	}
	return fmt.Errorf("%w\n\nThis rotation attempt was automatically reverted: %s and the local keyring are both "+
		"back to what they held before this attempt, and no managed file was ever touched.%s Fix the problem above, "+
		"then re-run `nebel rotate`; it will mint version %[4]d again, with a newly generated key, not this "+
		"attempt's.", cause, config.FileName, passwordNote, a.newVersion)
}

// printGeneratedPasswordNotice reports an auto-generated password the
// moment it exists (AC-11.8's no-secrets-beyond-the-password constraint),
// rather than waiting for rotation to fully succeed: this is the only
// place the password is ever shown, so it must not be deferred past any
// step — key registration, config save, re-encryption — that could still
// fail (audit 2026-09-30, R03).
func printGeneratedPasswordNotice(password string) {
	fmt.Printf("Generated new password: %s\n", password)
	fmt.Println("⚠ This password will not be shown again — store it in your password")
	fmt.Println("  manager now and share it with your team out-of-band.")
	fmt.Println()
}

// printRotateSummary reports AC-11.7's required consequences.
func printRotateSummary(newVersion int, migrated []string) {
	fmt.Printf("Rotated to key version %d and re-encrypted %s under it.\n", newVersion, plural(len(migrated), "file"))
	fmt.Println()
	fmt.Println("Staged:")
	fmt.Printf("  %s\n", config.FileName)
	for _, path := range migrated {
		fmt.Printf("  %s\n", path)
	}
	fmt.Println()
	fmt.Println("Commit when ready:")
	fmt.Println(`  git commit -m "rotate encryption key"`)
	fmt.Println()
	fmt.Printf("Once that commit exists, every field on this branch is tagged version %d.\n", newVersion)
	fmt.Println("Another clone's next `git pull` still succeeds — content it can't yet")
	fmt.Println("decrypt is left as ciphertext with a warning, the same as before its first")
	fmt.Println("`nebel init` — but it needs the new password to read or write any of it:")
	fmt.Println()
	fmt.Println("  git pull")
	fmt.Println("  nebel init   # with the new password")
	fmt.Println()
	fmt.Println("Rotation is forward-only: anyone who had the old password can still")
	fmt.Println("decrypt this repository's history from before the rotation commit. If it")
	fmt.Println("leaked, change the underlying secrets too, not just the password.")
}

// checkFullyDecryptable reports an error naming every managed file or
// field this clone cannot currently decrypt (scanUndecrypted). Rotate's
// eager re-encryption only ever re-cleans whatever the working tree
// already holds as plaintext (clean skips anything still tagged, spec 06
// AC-6.4, so it never double-encrypts a value this clone can't read);
// anything that currently shows up as ENC[...] here is content clean
// will keep skipping forever, forever pinned to whatever version
// produced it. Rotating on top of that would still succeed and would
// still mint a new version — it would just quietly leave part of the
// repo unreadable under it, which is exactly what rotate exists to
// prevent.
func checkFullyDecryptable(root string, cfg *config.Config) error {
	found, err := scanUndecrypted(root, cfg)
	if err != nil {
		return err
	}
	if len(found) == 0 {
		return nil
	}

	lines := make([]string, len(found))
	for i, s := range found {
		if s.Field == "" {
			lines[i] = fmt.Sprintf("  %s (%s)", s.Path, s.describe())
		} else {
			lines[i] = fmt.Sprintf("  %s at %s (%s)", s.Path, s.Field, s.describe())
		}
	}
	sort.Strings(lines)
	return fmt.Errorf(
		"rotate refused: this clone cannot currently decrypt everything it manages, "+
			"so rotating would strand the following on their existing version instead of "+
			"converging them onto the new one — register the missing key version(s) with "+
			"`nebel init --version N` and try again:\n%s",
		strings.Join(lines, "\n"))
}
