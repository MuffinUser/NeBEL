// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/MuffinUser/nebel/internal/config"
	"github.com/MuffinUser/nebel/internal/format"
	"github.com/MuffinUser/nebel/internal/gitutil"
)

const gitattributesName = ".gitattributes"

const addUsage = `usage:
  nebel add file <glob>            encrypt whole files matching <glob>
  nebel add field <file> [path...] encrypt named values inside <file>`

// runAdd dispatches the two kinds of rule (spec 08). They are separate
// subcommands rather than one command with a flag because they produce
// different rules, take different arguments, and are chosen for different
// reasons: whole-file for blobs with no readable structure, per-value for
// config you still want to diff.
func runAdd(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%s", addUsage)
	}
	switch args[0] {
	case "file":
		return runAddFile(args[1:])
	case "field":
		return runAddField(args[1:])
	}
	return fmt.Errorf("unknown subcommand %q\n%s", args[0], addUsage)
}

// openConfig loads the committed config, returning the repository root and
// the config's path alongside it since every caller needs all three.
func openConfig() (root, configPath string, cfg *config.Config, err error) {
	root, err = gitutil.RepoRoot()
	if err != nil {
		return "", "", nil, err
	}
	configPath = filepath.Join(root, config.FileName)
	if !config.Exists(configPath) {
		return "", "", nil, fmt.Errorf("no %s found — run `nebel init` first", config.FileName)
	}
	cfg, err = config.Load(configPath)
	if err != nil {
		return "", "", nil, err
	}
	return root, configPath, cfg, nil
}

// runAddFile implements `nebel add file <glob>` (AC-8.1).
func runAddFile(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("usage: nebel add file <glob>")
	}
	glob := normalizePath(args[0])

	root, configPath, cfg, err := openConfig()
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

// runAddField implements `nebel add field <file> [path...]` (AC-8.2).
//
// The file argument doubles as the rule's pattern and as the document the
// paths are checked against: a path that doesn't resolve is refused here,
// rather than failing later on whoever first stages the file.
//
// With no paths given, the file's scalars are listed for interactive
// selection, so nobody has to hand-write dot notation for a nested key.
func runAddField(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: nebel add field <file> [path...]")
	}
	target, paths := normalizePath(args[0]), args[1:]

	root, configPath, cfg, err := openConfig()
	if err != nil {
		return err
	}

	// The document is read from the working tree, so the argument has to
	// name a real file.
	source, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(target)))
	if err != nil {
		return fmt.Errorf("reading %s: %w", target, err)
	}
	handler, err := format.For(target)
	if err != nil {
		return err
	}

	existing := existingFields(cfg, target)
	if len(paths) == 0 {
		if paths, err = pickFields(handler, source, target, existing); err != nil {
			return err
		}
	}

	added, err := validateFields(handler, source, paths, existing)
	if err != nil {
		return err
	}
	if len(added) == 0 {
		fmt.Printf("No new fields to add for %s.\n", target)
		return addGitattributesPattern(root, target)
	}

	if err := applyFieldRule(cfg, target, added); err != nil {
		return err
	}
	if err := cfg.Save(configPath); err != nil {
		return err
	}
	if err := addGitattributesPattern(root, target); err != nil {
		return err
	}

	fmt.Printf("Added to rule %s (mode: value):\n", target)
	for _, path := range added {
		fmt.Printf("  %s\n", path)
	}
	return nil
}

// normalizePath gives a CLI path or glob the repo-relative, slash-separated
// form git reports, so it matches what MatchRule later compares it against.
func normalizePath(path string) string {
	return filepath.ToSlash(filepath.Clean(path))
}

// existingFields returns the paths already configured for pattern.
func existingFields(cfg *config.Config, pattern string) map[string]bool {
	fields := map[string]bool{}
	for _, r := range cfg.Rules {
		if r.Files == pattern {
			for _, field := range r.Encrypt {
				fields[field] = true
			}
		}
	}
	return fields
}

// validateFields checks each requested path against the document and drops
// the ones already configured, so re-running the command is a no-op
// (AC-8.5).
func validateFields(handler format.Handler, source []byte, paths []string, existing map[string]bool) ([]string, error) {
	var added []string
	seen := map[string]bool{}
	for _, path := range paths {
		if _, err := handler.Locate(source, path); err != nil {
			return nil, err
		}
		if existing[path] || seen[path] {
			continue
		}
		seen[path] = true
		added = append(added, path)
	}
	return added, nil
}

// applyFieldRule appends the paths to the pattern's rule, creating a
// mode: value rule if there isn't one yet.
func applyFieldRule(cfg *config.Config, pattern string, added []string) error {
	for i, r := range cfg.Rules {
		if r.Files != pattern {
			continue
		}
		if r.Mode != config.ModeValue {
			return fmt.Errorf("%q is already registered with mode: %s — remove that rule first, or pick a different pattern", pattern, r.Mode)
		}
		cfg.Rules[i].Encrypt = append(cfg.Rules[i].Encrypt, added...)
		return nil
	}
	cfg.Rules = append(cfg.Rules, config.Rule{Files: pattern, Mode: config.ModeValue, Encrypt: added})
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

// addGitattributesPattern appends a "<glob> filter=nebel" line wiring
// glob to the nebel filter, unless that exact line is already present.
func addGitattributesPattern(root, glob string) error {
	path := filepath.Join(root, gitattributesName)
	line := fmt.Sprintf("%s filter=nebel", escapeGitattributesPattern(glob))

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

// escapeGitattributesPattern escapes the characters gitattributes' line
// syntax gives special meaning to, so a glob written verbatim into a
// pattern/attribute line still means what the caller intended:
//   - a leading '#' starts a comment, and a leading '!' negates a
//     pattern — either would silently turn the whole line into something
//     other than a filter assignment for glob;
//   - the line's fields are split on whitespace, so an embedded space
//     would attach the rest of glob to the "filter=nebel" attribute
//     instead of the pattern, leaving the intended file unmatched even
//     though the command reports success.
//
// This does not touch glob metacharacters (*, ?, [, ], \) themselves —
// Rule.Files is intentionally a doublestar glob (see its doc comment),
// and escaping those would change what the pattern matches instead of
// merely how the line is parsed.
func escapeGitattributesPattern(glob string) string {
	if strings.HasPrefix(glob, "#") || strings.HasPrefix(glob, "!") {
		glob = `\` + glob
	}
	return strings.ReplaceAll(glob, " ", `\ `)
}
