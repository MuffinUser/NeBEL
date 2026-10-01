// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package localkey

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
)

// TestMain lets this test binary re-exec itself as a bare-bones worker
// process that does nothing but call Set(version, key) once. Real
// separate processes are needed because lockFile's flock/LockFileEx
// already correctly serializes concurrent goroutines within one process
// too (see setMu's doc comment) — only distinct processes, each with
// their own keyring read before any of them writes, can reproduce the
// lost-update race this test is checking is now closed.
func TestMain(m *testing.M) {
	if os.Getenv("NEBEL_CROSSPROCESS_HELPER") == "1" {
		version, _ := strconv.Atoi(os.Args[1])
		key := []byte(os.Args[2])
		if err := Set(version, key); err != nil {
			fmt.Fprintln(os.Stderr, "helper Set failed:", err)
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// Regression test for the 2026-09-30 reanalysis's finding 4.3: Set's
// read-modify-write of the key file was serialized only within one
// process (setMu); two concurrent `nebel` processes could each read the
// same old content and then each write back a different, equally
// "complete" update, silently losing whichever one lost the race — a real
// run of this test's predecessor, before the lockFile fix, lost 37 of 60
// concurrent registrations in a single run.
func TestCrossProcessSetDoesNotLoseUpdates(t *testing.T) {
	dir := t.TempDir()
	runGit(t, dir, "init", "-q")
	runGit(t, dir, "config", "user.email", "t@t.com")
	runGit(t, dir, "config", "user.name", "t")

	// localkey resolves the key file path relative to the current
	// process's git repo (gitCommonDir), so both this parent (which reads
	// back the result via All()) and every helper subprocess it launches
	// need their working directory set to dir — a helper's cmd.Dir alone
	// covers the subprocess, but not this process's own later All() call.
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	t.Cleanup(func() { os.Chdir(orig) })
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("Chdir: %v", err)
	}

	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}

	const n = 60
	var wg sync.WaitGroup
	results := make([]error, n)
	for i := 0; i < n; i++ {
		version := i + 1
		wg.Add(1)
		go func(idx, version int) {
			defer wg.Done()
			cmd := exec.Command(exe, strconv.Itoa(version), fmt.Sprintf("key-for-v%d", version))
			cmd.Env = append(os.Environ(), "NEBEL_CROSSPROCESS_HELPER=1")
			cmd.Dir = dir
			out, err := cmd.CombinedOutput()
			if err != nil {
				results[idx] = fmt.Errorf("version %d: %v: %s", version, err, out)
			}
		}(i, version)
	}
	wg.Wait()

	for _, err := range results {
		if err != nil {
			t.Fatalf("helper process itself failed (not the race under test): %v", err)
		}
	}

	all, err := All()
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	var missing []int
	for i := 0; i < n; i++ {
		version := i + 1
		if _, ok := all[version]; !ok {
			missing = append(missing, version)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d/%d versions reported Set() success but are missing from the final key file (lost update across processes): %v", len(missing), n, missing)
	}
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out.String())
	}
}
