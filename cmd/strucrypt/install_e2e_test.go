package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pathEnvWithoutBin is the environment an IDE hands to git after
// strucrypt was installed underneath it: git and the usual tools are
// there, strucrypt is not, because the PATH entry the installer added
// postdates the process that is running.
//
// Every directory holding a strucrypt binary is dropped, not just the
// test's own build directory — a developer machine commonly has a real
// strucrypt in /usr/local/bin, and leaving it reachable would let a
// bare-name registration resolve and quietly pass these tests.
func pathEnvWithoutBin(t *testing.T) string {
	t.Helper()
	ensureBinary(t)

	var kept []string
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || dir == binDir || hasStrucrypt(dir) {
			continue
		}
		kept = append(kept, dir)
	}
	pathEnv := strings.Join(kept, string(os.PathListSeparator))

	// Fail loudly rather than test nothing if the filtering missed one.
	if dir, found := lookupOnPath(pathEnv); found {
		t.Fatalf("strucrypt is still reachable at %s after filtering PATH", dir)
	}
	return pathEnv
}

func hasStrucrypt(dir string) bool {
	_, found := lookupOnPath(dir)
	return found
}

func lookupOnPath(pathEnv string) (string, bool) {
	for _, dir := range filepath.SplitList(pathEnv) {
		for _, name := range []string{"strucrypt", "strucrypt.exe"} {
			if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
				return filepath.Join(dir, name), true
			}
		}
	}
	return "", false
}

// The regression this whole change exists for: once `strucrypt init` has
// run, a full git round trip must work even though nothing on git's PATH
// is called strucrypt. Registering the filter as a bare name fails here.
func TestFilterRunsWithStrucryptOffPath(t *testing.T) {
	setupPath := pathEnvWithBin(t)
	repo := newTestRepo(t, setupPath)

	// Install-time: strucrypt is reachable, as it is in the fresh
	// terminal the user installs from.
	initWithPassword(t, repo, setupPath, "test-password-123")
	runIn(t, repo, setupPath, "strucrypt", "add", "secrets/*.pem")

	// Everything after this point runs as the IDE would run it.
	idePath := pathEnvWithoutBin(t)

	secretsDir := filepath.Join(repo, "secrets")
	if err := os.MkdirAll(secretsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	plaintext := "-----BEGIN KEY-----\noff-path-secret\n-----END KEY-----\n"
	secretPath := filepath.Join(secretsDir, "prod.pem")
	if err := os.WriteFile(secretPath, []byte(plaintext), 0o644); err != nil {
		t.Fatal(err)
	}

	runIn(t, repo, idePath, "git", "add", ".")
	runIn(t, repo, idePath, "git", "commit", "-q", "-m", "add secret from the IDE")

	// filter.strucrypt.required = true means a filter git could not run
	// aborts the commit, so reaching here already proves clean ran. Check
	// the blob anyway: a silently skipped filter would store plaintext.
	stored := runIn(t, repo, idePath, "git", "show", "HEAD:secrets/prod.pem")
	if !strings.HasPrefix(stored, "ENC[") {
		t.Fatalf("blob committed with strucrypt off PATH is not encrypted: %q", stored)
	}

	if err := os.Remove(secretPath); err != nil {
		t.Fatal(err)
	}
	runIn(t, repo, idePath, "git", "checkout", "--", "secrets/prod.pem")

	restored, err := os.ReadFile(secretPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != plaintext {
		t.Errorf("checked-out file = %q, want %q", restored, plaintext)
	}
}

// init must record an absolute path, not the bare name earlier versions
// wrote — the property the test above depends on.
func TestInitRegistersAbsoluteFilterPath(t *testing.T) {
	pathEnv := pathEnvWithBin(t)
	repo := newTestRepo(t, pathEnv)
	initWithPassword(t, repo, pathEnv, "test-password-123")

	for _, sub := range []string{"clean", "smudge"} {
		key := "filter.strucrypt." + sub
		got := strings.TrimSpace(runIn(t, repo, pathEnv, "git", "config", "--local", "--get", key))
		if !strings.HasSuffix(got, " "+sub+" %f") {
			t.Errorf("%s = %q, want it to end in %q", key, got, " "+sub+" %f")
		}
		if strings.HasPrefix(got, "strucrypt") {
			t.Errorf("%s = %q, still registered as a bare PATH-dependent name", key, got)
		}
		if !strings.Contains(got, binDir) && !strings.Contains(got, filepath.ToSlash(binDir)) {
			t.Errorf("%s = %q, want it to name the binary in %s", key, got, binDir)
		}
	}
}

// AC-11.5: re-running init is the documented repair for a clone carrying
// the bare-name registration an older strucrypt wrote.
func TestInitRepairsBareNameRegistration(t *testing.T) {
	setupPath := pathEnvWithBin(t)
	repo := newTestRepo(t, setupPath)
	initWithPassword(t, repo, setupPath, "test-password-123")
	runIn(t, repo, setupPath, "strucrypt", "add", "secrets/*.pem")

	// Wind the clone back to what an older version left behind.
	for _, sub := range []string{"clean", "smudge"} {
		runIn(t, repo, setupPath, "git", "config", "--local",
			"filter.strucrypt."+sub, "strucrypt "+sub+" %f")
	}

	// The repair has to work from the broken environment itself, which is
	// where the user actually is when they hit this.
	idePath := pathEnvWithoutBin(t)
	initWithPassword(t, repo, idePath, "test-password-123")

	for _, sub := range []string{"clean", "smudge"} {
		key := "filter.strucrypt." + sub
		got := strings.TrimSpace(runIn(t, repo, idePath, "git", "config", "--local", "--get", key))
		if strings.HasPrefix(got, "strucrypt") {
			t.Errorf("%s = %q, re-running init left the bare name in place", key, got)
		}
	}

	// And the repaired clone genuinely filters, with strucrypt off PATH.
	secretsDir := filepath.Join(repo, "secrets")
	if err := os.MkdirAll(secretsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretsDir, "prod.pem"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	runIn(t, repo, idePath, "git", "add", ".")
	runIn(t, repo, idePath, "git", "commit", "-q", "-m", "after repair")
	if stored := runIn(t, repo, idePath, "git", "show", "HEAD:secrets/prod.pem"); !strings.HasPrefix(stored, "ENC[") {
		t.Errorf("blob after repair is not encrypted: %q", stored)
	}
}
