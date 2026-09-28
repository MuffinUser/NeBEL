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
	"github.com/MuffinUser/nebel/internal/format"
	"github.com/MuffinUser/nebel/internal/gitutil"
	"github.com/MuffinUser/nebel/internal/kdf"
	"github.com/MuffinUser/nebel/internal/localkey"
	"github.com/MuffinUser/nebel/internal/tag"
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

	// AC-11.5: register the new key before saving the config. If the
	// config write below failed after this, this machine would still be
	// able to clean under the new version on retry; the reverse order
	// could leave a saved config this machine can't yet use.
	if err := localkey.Set(newVersion, newKey); err != nil {
		return fmt.Errorf("registering local key: %w", err)
	}
	if err := next.Save(configPath); err != nil {
		return err
	}

	// Stage the config, then eagerly re-encrypt every managed file/field
	// under the version just minted, so it's never left to be remembered
	// as a manual follow-up (this used to be the documented `git add
	// --renormalize` escape hatch, spec 11 AC-11.10 — rotate now runs it
	// itself). checkFullyDecryptable above guarantees this actually
	// reaches everything: nothing left encrypted going in means nothing
	// comes out still tagged with the old version.
	if err := gitutil.Add(root, config.FileName); err != nil {
		return err
	}
	migrated, err := gitutil.RenormalizeAll(root)
	if err != nil {
		return fmt.Errorf("re-encrypting existing content under the new version: %w", err)
	}

	printRotateSummary(newVersion, generated, password, migrated)
	return nil
}

// printRotateSummary reports AC-11.7's required consequences and AC-11.8's
// no-secrets-beyond-the-password constraint.
func printRotateSummary(newVersion int, generated bool, password string, migrated []string) {
	if generated {
		fmt.Printf("Generated new password: %s\n", password)
		fmt.Println("⚠ This password will not be shown again — store it in your password")
		fmt.Println("  manager now and share it with your team out-of-band.")
		fmt.Println()
	}

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
	fmt.Printf("Once that commit exists, every field on this branch is tagged version\n")
	fmt.Printf("%d — a plain `git pull` on another clone will fail (it needs the new key\n", newVersion)
	fmt.Printf("to read the changed files) until that clone runs:\n")
	fmt.Println()
	fmt.Println("  git fetch")
	fmt.Println("  git show @{u}:.nebel.yaml > .nebel.yaml   # not filter-managed, always safe")
	fmt.Printf("  nebel init                                # with the new password\n")
	fmt.Println("  git add -u                                 # re-stage so nothing looks locally modified")
	fmt.Println("  git pull")
	fmt.Println()
	fmt.Println("Rotation is forward-only: anyone who had the old password can still")
	fmt.Println("decrypt this repository's history from before the rotation commit. If it")
	fmt.Println("leaked, change the underlying secrets too, not just the password.")
}

// checkFullyDecryptable reports an error naming every managed file or
// field this clone cannot currently decrypt. Rotate's eager re-encryption
// only ever re-cleans whatever the working tree already holds as
// plaintext (clean skips anything still tagged, spec 06 AC-6.4, so it
// never double-encrypts a value this clone can't read); anything that
// currently shows up as ENC[...] here is content clean will keep skipping
// forever, forever pinned to whatever version produced it. Rotating on
// top of that would still succeed and would still mint a new version —
// it would just quietly leave part of the repo unreadable under it,
// which is exactly what rotate exists to prevent.
func checkFullyDecryptable(root string, cfg *config.Config) error {
	files, err := gitutil.ManagedFiles(root)
	if err != nil {
		return err
	}

	var stuck []string
	for _, f := range files {
		rule, ok := cfg.MatchRule(f)
		if !ok {
			continue
		}
		content, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			stuck = append(stuck, fmt.Sprintf("  %s (could not be read: %v)", f, err))
			continue
		}

		if rule.Mode != config.ModeValue {
			if tag.IsEncrypted(content) {
				stuck = append(stuck, fmt.Sprintf("  %s (%s)", f, describeTag(content)))
			}
			continue
		}

		handler, err := format.For(f)
		if err != nil {
			return fmt.Errorf("checking %s: %w", f, err)
		}
		for _, field := range rule.Encrypt {
			span, err := handler.Locate(content, field)
			if err != nil {
				return fmt.Errorf("checking %s: %w", f, err)
			}
			if tag.IsEncrypted([]byte(span.Value)) {
				stuck = append(stuck, fmt.Sprintf("  %s at %s (%s)", f, field, describeTag([]byte(span.Value))))
			}
		}
	}
	if len(stuck) == 0 {
		return nil
	}

	sort.Strings(stuck)
	return fmt.Errorf(
		"rotate refused: this clone cannot currently decrypt everything it manages, "+
			"so rotating would strand the following on their existing version instead of "+
			"converging them onto the new one — register the missing key version(s) with "+
			"`nebel init --version N` and try again:\n%s",
		strings.Join(stuck, "\n"))
}

// describeTag names the key version a still-encrypted span is stuck on,
// for checkFullyDecryptable's error — falling back to a generic label if
// the tag itself doesn't even parse (a distinct, worse problem, but not
// this function's job to diagnose).
func describeTag(raw []byte) string {
	parsed, err := tag.Parse(string(raw))
	if err != nil {
		return "malformed tag"
	}
	return fmt.Sprintf("needs key version %d", parsed.Version)
}
