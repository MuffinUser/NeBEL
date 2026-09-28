// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

package main

import (
	"fmt"
	"os"
)

// version is set at release build time via -ldflags "-X main.version=...".
// A plain `go build` (local dev) leaves it at "dev".
var version = "dev"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "init":
		err = runInit(os.Args[2:])
	case "add":
		err = runAdd(os.Args[2:])
	case "rotate":
		err = runRotate(os.Args[2:])
	case "clean":
		err = runClean(os.Args[2:])
	case "smudge":
		err = runSmudge(os.Args[2:])
	case "version":
		fmt.Println("nebel", version)
		fmt.Println("Copyright (C) 2026 Marwin Moellers")
		fmt.Println("License GPLv3+: GNU GPL version 3 or later <https://gnu.org/licenses/gpl.html>")
		fmt.Println("This is free software: you are free to change and redistribute it.")
		fmt.Println("There is NO WARRANTY, to the extent permitted by law.")
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "nebel:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  nebel init [--password-stdin]
                                 bootstrap or join a repo. The password is
                                 read from $NEBEL_PASSWORD, from stdin
                                 with --password-stdin, or prompted for
  nebel init --version N [--password-stdin]
                                 fetch and register a specific (possibly
                                 non-current) key version's key locally
  nebel add file <glob>      encrypt whole files matching <glob>
  nebel add field <file> [path...]
                                 encrypt named values inside <file>;
                                 with no paths, choose them interactively
  nebel rotate [--password-stdin]
                                 mint a new, current key version; does not
                                 touch already-encrypted content
  nebel clean <path>         (invoked by git) encrypt stdin to stdout
  nebel smudge <path>        (invoked by git) decrypt stdin to stdout
  nebel version              print the build version`)
}
