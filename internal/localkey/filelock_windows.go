// Copyright (C) 2026 Marwin Moellers
// SPDX-License-Identifier: GPL-3.0-or-later

//go:build windows

package localkey

import (
	"os"

	"golang.org/x/sys/windows"
)

// fileLock holds an exclusive, advisory, cross-process lock on the file it
// was opened for (see lockFile).
type fileLock struct {
	f *os.File
}

// lockFile opens (creating if necessary) the file at path and blocks until
// it holds an exclusive LockFileEx lock on it — this platform's equivalent
// of the Unix flock lockFile (filelock_unix.go) takes, released
// automatically if this process dies while holding it.
func lockFile(path string) (*fileLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	var overlapped windows.Overlapped
	// One byte is enough to lock: this file is never read or written
	// through the handle itself, only used as a mutex.
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &overlapped); err != nil {
		f.Close()
		return nil, err
	}
	return &fileLock{f: f}, nil
}

// Unlock releases the lock and closes the underlying file handle.
func (l *fileLock) Unlock() error {
	defer l.f.Close()
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(l.f.Fd()), 0, 1, 0, &overlapped)
}
