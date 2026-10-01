// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build !windows

package localkey

import (
	"os"

	"golang.org/x/sys/unix"
)

// fileLock holds an exclusive, advisory, cross-process lock on the file it
// was opened for (see lockFile).
type fileLock struct {
	f *os.File
}

// lockFile opens (creating if necessary) the file at path and blocks until
// it holds an exclusive flock on it. flock's lock is released automatically
// if this process dies while holding it (unlike a lock file whose mere
// existence signals "locked" — that kind can't tell a crashed holder from
// a live one, and needs its own stale-lock cleanup), so a `nebel` process
// killed mid-Set never leaves the key file permanently unwritable to
// others.
func lockFile(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// Unlock releases the lock and closes the underlying file handle.
func (l *fileLock) Unlock() error {
	defer l.f.Close()
	return unix.Flock(int(l.f.Fd()), unix.LOCK_UN)
}
