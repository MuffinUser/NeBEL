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
	case "clean":
		err = runClean(os.Args[2:])
	case "smudge":
		err = runSmudge(os.Args[2:])
	case "version":
		fmt.Println("strucrypt", version)
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintln(os.Stderr, "strucrypt:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  strucrypt init [--password-stdin]
                                 bootstrap or join a repo. The password is
                                 read from $STRUCRYPT_PASSWORD, from stdin
                                 with --password-stdin, or prompted for
  strucrypt add <glob>           register a whole-file rule
  strucrypt clean <path>         (invoked by git) encrypt stdin to stdout
  strucrypt smudge <path>        (invoked by git) decrypt stdin to stdout
  strucrypt version              print the build version`)
}
