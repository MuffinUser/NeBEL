package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/MarwinMoellers/strucrypt/internal/config"
	"github.com/MarwinMoellers/strucrypt/internal/gitutil"
	"github.com/MarwinMoellers/strucrypt/internal/kdf"
	"github.com/MarwinMoellers/strucrypt/internal/localkey"
)

// runInit implements `strucrypt init [password]`, auto-detecting bootstrap
// vs. join mode by whether .strucrypt.yaml already exists (spec 07).
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

	// Join mode needs a password and prompts for one if no source supplied
	// it; bootstrap mode generates one instead (AC-7.2).
	joining := config.Exists(configPath)
	password, err := input.resolve(joining)
	if err != nil {
		return err
	}

	if joining {
		return joinRepo(root, configPath, password)
	}
	return bootstrapRepo(root, configPath, password)
}

const initUsage = "usage: strucrypt init [--password-stdin]"

func parseInitArgs(args []string) (passwordInput, error) {
	var input passwordInput
	for _, arg := range args {
		switch {
		case arg == "--password-stdin":
			input.fromStdin = true
		case strings.HasPrefix(arg, "-"):
			return input, fmt.Errorf("unknown flag %q\n%s", arg, initUsage)
		default:
			// The only positional `init` ever took was the password.
			return input, ErrPasswordArgument
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

	canary, err := config.NewCanary(key)
	if err != nil {
		return err
	}

	cfg := &config.Config{
		Salt:   base64.StdEncoding.EncodeToString(salt),
		Canary: canary,
		Rules:  []config.Rule{},
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
	if err := localkey.Set(key); err != nil {
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
	fmt.Println("Run `strucrypt add <glob>` to register files to encrypt.")
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
	if err := localkey.Set(key); err != nil {
		return fmt.Errorf("registering local key: %w", err)
	}

	fmt.Println("Password verified.")
	fmt.Println("Local filter registered.")
	fmt.Println("Re-checking out managed files...")
	if err := gitutil.CheckoutAll(root); err != nil {
		return fmt.Errorf("re-checking out files: %w", err)
	}
	fmt.Println("Done.")
	return nil
}

// registerFilter points this clone's local git config at the strucrypt
// binary that is running right now, by absolute path — see
// gitutil.FilterCommand for why a bare "strucrypt" on PATH is not enough.
func registerFilter() error {
	for _, sub := range []string{"clean", "smudge"} {
		cmd, err := gitutil.SelfFilterCommand(sub)
		if err != nil {
			return err
		}
		if err := gitutil.ConfigSet("filter.strucrypt."+sub, cmd); err != nil {
			return err
		}
	}
	return gitutil.ConfigSet("filter.strucrypt.required", "true")
}

// generatePassword returns a high-entropy, URL-safe random password.
// 24 random bytes (192 bits) base64url-encoded, 32 characters, no padding.
func generatePassword() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
