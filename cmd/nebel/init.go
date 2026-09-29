// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/gitutil"
	"github.com/MuffinUser/nebel/internal/kdf"
	"github.com/MuffinUser/nebel/internal/localkey"
)

// runInit implements `nebel init [password]` and `nebel init --version N
// [password]`, auto-detecting bootstrap vs. join mode by whether
// .nebel.yaml already exists (spec 07).
func runInit(args []string) error {
	input, err := parseInitArgs(args)
	if err != nil {
		return err
	}

	root, err := gitutil.RepoRoot()
	if err != nil {
		return err
	}
	configPath := filepath.Join(root, config.FileName)

	// --version N (spec 07 § Fetching an older key version) always needs a
	// real password for that specific version — there's no bootstrap-style
	// "generate one instead" fallback, since a password can't be invented
	// for a version that already exists.
	if input.version != nil {
		if !config.Exists(configPath) {
			return fmt.Errorf("no %s found — run `nebel init` first to bootstrap", config.FileName)
		}
		password, err := input.password.resolve(true)
		if err != nil {
			return err
		}
		return initVersion(root, configPath, *input.version, password)
	}

	// Join mode needs a password and prompts for one if no source supplied
	// it; bootstrap mode generates one instead (AC-7.2).
	joining := config.Exists(configPath)
	password, err := input.password.resolve(joining)
	if err != nil {
		return err
	}

	if joining {
		return joinRepo(root, configPath, password)
	}
	return bootstrapRepo(root, configPath, password)
}

const initUsage = "usage: nebel init [--password-stdin] [--version N]"

// initArgs is `init`'s parsed command line: a password source, plus an
// optional specific version to fetch (spec 07 AC-7.14) instead of
// bootstrapping or joining at the config's current version.
type initArgs struct {
	password passwordInput
	version  *int
}

func parseInitArgs(args []string) (initArgs, error) {
	var result initArgs
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--password-stdin":
			result.password.fromStdin = true
		case arg == "--version":
			i++
			if i >= len(args) {
				return result, fmt.Errorf("--version requires a value\n%s", initUsage)
			}
			n, err := strconv.Atoi(args[i])
			if err != nil || n < 1 {
				return result, fmt.Errorf("--version: invalid version %q\n%s", args[i], initUsage)
			}
			result.version = &n
		case strings.HasPrefix(arg, "-"):
			return result, fmt.Errorf("unknown flag %q\n%s", arg, initUsage)
		default:
			// The only positional `init` ever took was the password.
			return result, ErrPasswordArgument
		}
	}
	return result, nil
}

// parsePasswordFlags parses the --password-stdin flag shared by `rotate`
// with the password half of `init`'s command line (spec 07 § Password
// input; spec 11 AC-11.3). Neither command ever took a positional password
// argument, so any other bare argument is refused with argErr, naming that
// command's supported alternatives.
func parsePasswordFlags(args []string, usage string, argErr error) (passwordInput, error) {
	var input passwordInput
	for _, arg := range args {
		switch {
		case arg == "--password-stdin":
			input.fromStdin = true
		case strings.HasPrefix(arg, "-"):
			return input, fmt.Errorf("unknown flag %q\n%s", arg, usage)
		default:
			return input, argErr
		}
	}
	return input, nil
}

func bootstrapRepo(root, configPath, password string) error {
	generated := password == ""
	if generated {
		password = generatePassword()
	}

	salt := kdf.NewSalt()
	key, err := kdf.Derive(password, salt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}

	canary, err := config.NewCanary(key, 1)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		FormatVersion: config.CurrentFormatVersion,
		CreatedWith:   buildVersion(), // informational only — see Config.CreatedWith.
		KeyVersion:    1,              // AC-4.10: bootstrap always starts at version 1.
		Salt:          base64.StdEncoding.EncodeToString(salt),
		Canary:        canary,
		Rules:         []config.Rule{},
	}

	// AC-7.4: the config we're about to commit must be self-consistent
	// before we tell the user bootstrap succeeded.
	if err := cfg.VerifyCanary(key); err != nil {
		return fmt.Errorf("internal error: freshly created canary did not verify: %w", err)
	}

	if err := cfg.Save(configPath); err != nil {
		return err
	}
	if err := ensureGitattributes(root); err != nil {
		return err
	}
	if err := registerFilter(); err != nil {
		return err
	}
	if err := localkey.Set(cfg.CurrentVersion(), key); err != nil {
		return fmt.Errorf("registering local key: %w", err)
	}

	if generated {
		fmt.Printf("Generated password: %s\n", password)
		fmt.Println("⚠ This password will not be shown again — store it in your password")
		fmt.Println("  manager now and share it with your team out-of-band.")
		fmt.Println()
	}
	fmt.Println("Created:")
	fmt.Printf("  %s   (encryption rules config — commit this)\n", config.FileName)
	fmt.Println("  .gitattributes    (filter assignment — commit this)")
	fmt.Println()
	fmt.Println("Local filter registered. You're ready to use git normally.")
	fmt.Println("Run `nebel add <glob>` to register files to encrypt.")
	return nil
}

// joinRepo is reached with a non-empty password: runInit resolves one from
// the environment, stdin, an argument, or an interactive prompt before
// deciding which mode to run.
func joinRepo(root, configPath, password string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}
	salt, err := cfg.SaltBytes()
	if err != nil {
		return err
	}
	key, err := kdf.Derive(password, salt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}

	if err := cfg.VerifyCanary(key); err != nil {
		// AC-7.7: wrong password must not register the filter.
		return fmt.Errorf("password does not match this repo's canary: %w", err)
	}

	if err := registerFilter(); err != nil {
		return err
	}
	if err := localkey.Set(cfg.CurrentVersion(), key); err != nil {
		return fmt.Errorf("registering local key: %w", err)
	}

	fmt.Println("Password verified.")
	fmt.Println("Local filter registered.")
	fmt.Println("Re-checking out managed files...")
	decrypted, failures, err := gitutil.CheckoutAll(root)
	if err != nil {
		return fmt.Errorf("re-checking out files: %w", err)
	}
	return reportCheckoutResult(root, cfg, decrypted, failures)
}

// reportCheckoutResult prints CheckoutAll's outcome for join and
// --version alike: a plain "N decrypted" success, a diagnostic for
// "nothing is wired to the filter at all" (total == 0), or — with
// failures — each path and why, sourced two ways. CheckoutAll's own
// failures are genuine per-file checkout errors (AC-6.9's tamper error,
// say). But smudge no longer errors just because a version is missing
// (spec 06 AC-6.11): it passes the content through instead, with a
// warning already printed live during the checkout above, and
// CheckoutAll counts that as "decrypted" since the checkout itself
// succeeded. scanUndecrypted re-inspects the working tree afterward to
// catch exactly that gap, moving each still-encrypted path from
// "decrypted" to the report below (skipping any path CheckoutAll already
// flagged, so a genuine failure isn't listed twice under two different
// reasons).
func reportCheckoutResult(root string, cfg *config.Config, decrypted int, failures []gitutil.CheckoutFailure) error {
	alreadyReported := make(map[string]bool, len(failures))
	for _, f := range failures {
		alreadyReported[f.Path] = true
	}

	stillEncrypted, err := scanUndecrypted(root, cfg)
	if err != nil {
		return fmt.Errorf("checking what's still encrypted: %w", err)
	}
	byPath := map[string][]stuckContent{}
	var order []string
	for _, s := range stillEncrypted {
		if alreadyReported[s.Path] {
			continue
		}
		if _, seen := byPath[s.Path]; !seen {
			order = append(order, s.Path)
		}
		byPath[s.Path] = append(byPath[s.Path], s)
	}
	sort.Strings(order)
	for _, path := range order {
		var reasons []string
		for _, s := range byPath[path] {
			reason := s.describe()
			if s.Version >= 0 {
				// Unlike rotate's refusal error (which only ever finds
				// this from a clone that already holds the *current*
				// version's key, so every hint there is `--version N`),
				// init can hit either case: the version just rotated
				// past current, or an older one this clone never
				// fetched — worth spelling out which fix applies.
				reason = fmt.Sprintf("%s — %s", reason, fixHint(cfg, s.Version))
			}
			if s.Field != "" {
				reason = fmt.Sprintf("at %s, %s", s.Field, reason)
			}
			reasons = append(reasons, reason)
		}
		failures = append(failures, gitutil.CheckoutFailure{Path: path, Reason: strings.Join(reasons, "; ")})
		decrypted--
	}

	total := decrypted + len(failures)
	if total == 0 {
		// The password/version was right, so the key is fine — but
		// nothing in the repository is wired to the filter. Almost
		// always a .gitattributes that was never committed, which
		// otherwise looks exactly like a successful join that decrypted
		// nothing.
		fmt.Printf("Done, but no filter-managed files were found.\n"+
			"  Check that %s is committed and lists your patterns:\n"+
			"    git check-attr filter -- <path>   should report \"filter: nebel\"\n",
			gitattributesName)
		return nil
	}
	if len(failures) == 0 {
		fmt.Printf("Done. %s decrypted locally.\n", plural(decrypted, "file"))
		return nil
	}
	fmt.Printf("Done. %s decrypted locally; %s could not be:\n", plural(decrypted, "file"), plural(len(failures), "file"))
	for _, f := range failures {
		fmt.Printf("  %s: %s\n", f.Path, f.Reason)
	}
	return nil
}

// initVersion implements `nebel init --version N [password]` (spec 07
// AC-7.14–7.16): derives and verifies the key for a specific version,
// which need not be the config's current one, and adds it to the local
// keyring alongside whatever is already registered — never disturbing an
// existing entry.
func initVersion(root, configPath string, version int, password string) error {
	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	hist, err := config.LookupVersion(root, cfg, version)
	if err != nil {
		return err
	}
	histCfg := &config.Config{Salt: hist.Salt, Canary: hist.Canary}
	salt, err := histCfg.SaltBytes()
	if err != nil {
		return err
	}
	key, err := kdf.Derive(password, salt)
	if err != nil {
		return fmt.Errorf("deriving key: %w", err)
	}
	if err := histCfg.VerifyCanary(key); err != nil {
		return fmt.Errorf("password does not match key version %d's canary: %w", version, err)
	}

	// --version doesn't presuppose a prior plain `init` on this clone —
	// registering the filter here (idempotent, like join's) is what makes
	// checking out managed files below actually run them through smudge
	// instead of leaving them untouched by any filter driver at all.
	if err := registerFilter(); err != nil {
		return err
	}
	if err := localkey.Set(version, key); err != nil {
		return fmt.Errorf("registering local key: %w", err)
	}

	fmt.Printf("Key version %d verified and registered locally.\n", version)
	fmt.Println("Re-checking out managed files...")
	decrypted, failures, err := gitutil.CheckoutAll(root)
	if err != nil {
		return fmt.Errorf("re-checking out files: %w", err)
	}
	return reportCheckoutResult(root, cfg, decrypted, failures)
}

func registerFilter() error {
	if err := gitutil.ConfigSet("filter.nebel.clean", "nebel clean %f"); err != nil {
		return err
	}
	if err := gitutil.ConfigSet("filter.nebel.smudge", "nebel smudge %f"); err != nil {
		return err
	}
	return gitutil.ConfigSet("filter.nebel.required", "true")
}

// generatePassword returns a high-entropy, URL-safe random password.
// 24 random bytes (192 bits) base64url-encoded, 32 characters, no padding.
func generatePassword() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// plural renders a count with its noun: "1 file", "3 files".
func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
