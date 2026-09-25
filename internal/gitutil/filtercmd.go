package gitutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// FilterCommand builds the value for a filter.strucrypt.<sub> git config
// entry: the command line git runs for clean/smudge.
//
// It deliberately uses the absolute path to this executable rather than
// the bare name "strucrypt". Git resolves filter commands through a shell
// (sh -c on Windows, via Git for Windows' bundled MSYS sh), whose PATH is
// inherited from whatever process invoked git. That process is often not
// a fresh login shell: IntelliJ, for example, inherits its environment
// from the desktop session it was started in, so a PATH entry added by
// the installer is invisible to it — and to its embedded terminal and
// bundled git — until the IDE is fully restarted. Users hit "strucrypt:
// command not found" from the IDE while the same command works in a new
// terminal. An absolute path removes PATH from the equation entirely.
//
// On Windows the path is emitted with forward slashes, which git and
// MSYS sh both accept, and which avoids backslash escaping in the config
// file. It is double-quoted when it contains characters the shell would
// otherwise split or interpret — most commonly a space, as in
// "C:/Program Files/...".
func FilterCommand(exePath, sub string) string {
	return filterCommand(exePath, sub, runtime.GOOS == "windows")
}

// filterCommand takes the platform as an argument so both branches are
// testable from either host. The separator rewrite is deliberately gated:
// a backslash is a legal character in a Unix filename, so rewriting it
// there would corrupt the path rather than normalise it.
func filterCommand(exePath, sub string, windows bool) string {
	if windows {
		exePath = strings.ReplaceAll(exePath, `\`, "/")
	}
	return quoteForShell(exePath) + " " + sub + " %f"
}

// SelfFilterCommand is FilterCommand for the currently running binary.
// Symlinks are resolved so the recorded path stays valid independently of
// a symlink that may later be repointed or removed (Homebrew and
// /usr/local/bin installs are commonly symlinks).
func SelfFilterCommand(sub string) (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("gitutil: locating the strucrypt executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return FilterCommand(exe, sub), nil
}

// shellSafe is the set of characters that need no quoting in an sh word.
const shellSafe = "abcdefghijklmnopqrstuvwxyz" +
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"0123456789" + "._-+/:=@,"

func quoteForShell(s string) string {
	if s != "" && strings.IndexFunc(s, func(r rune) bool {
		return !strings.ContainsRune(shellSafe, r)
	}) < 0 {
		return s
	}
	// Double quotes, not single: git's own config parser and MSYS sh both
	// handle them, and a Windows path never legally contains " or \, the
	// only characters still special inside double quotes here.
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`, "$", `\$`, "`", "\\`").Replace(s) + `"`
}
