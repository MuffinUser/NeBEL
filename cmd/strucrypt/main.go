package main

import (
	"fmt"
	"os"
)

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
  strucrypt init [password]      bootstrap or join a repo
  strucrypt add <glob>           register a whole-file rule
  strucrypt clean <path>         (invoked by git) encrypt stdin to stdout
  strucrypt smudge <path>        (invoked by git) decrypt stdin to stdout`)
}
