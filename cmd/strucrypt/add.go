package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MarwinMoellers/strucrypt/internal/config"
	"github.com/MarwinMoellers/strucrypt/internal/gitutil"
)

const gitattributesName = ".gitattributes"

// runAdd implements `strucrypt add <glob>` (spec 08 AC-8.1). MVP scope:
// whole-file rules only — no --field, so per-value rules can't be created
// by this command (mode: value isn't implemented yet, see internal/config).
func runAdd(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: strucrypt add <glob>")
	}
	glob := args[0]

	root, err := gitutil.RepoRoot()
	if err != nil {
		return err
	}
	configPath := filepath.Join(root, config.FileName)
	if !config.Exists(configPath) {
		return fmt.Errorf("no %s found — run `strucrypt init` first", config.FileName)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	for _, r := range cfg.Rules {
		if r.Files != glob {
			continue
		}
		if r.Mode != config.ModeFile {
			return fmt.Errorf("%q is already registered with mode: %s — mode conflict", glob, r.Mode)
		}
		fmt.Printf("Rule already exists: %s (mode: file)\n", glob)
		return addGitattributesPattern(root, glob) // idempotent; covers a hand-edited config missing the .gitattributes line
	}

	cfg.Rules = append(cfg.Rules, config.Rule{Files: glob, Mode: config.ModeFile})
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	if err := addGitattributesPattern(root, glob); err != nil {
		return err
	}

	fmt.Printf("Added rule: %s (mode: file)\n", glob)
	return nil
}

// ensureGitattributes creates an empty .gitattributes file at bootstrap if
// one doesn't exist yet, so it's ready to commit even before any rule is
// added.
func ensureGitattributes(root string) error {
	path := filepath.Join(root, gitattributesName)
	if _, err := os.Stat(path); err == nil {
		return nil
	}
	return os.WriteFile(path, nil, 0o644)
}

// addGitattributesPattern appends a "<glob> filter=strucrypt" line wiring
// glob to the strucrypt filter, unless that exact line is already present.
func addGitattributesPattern(root, glob string) error {
	path := filepath.Join(root, gitattributesName)
	line := fmt.Sprintf("%s filter=strucrypt", glob)

	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", gitattributesName, err)
	}
	for _, l := range strings.Split(string(existing), "\n") {
		if strings.TrimSpace(l) == line {
			return nil
		}
	}

	content := string(existing)
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += line + "\n"

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		return fmt.Errorf("writing %s: %w", gitattributesName, err)
	}
	return nil
}
