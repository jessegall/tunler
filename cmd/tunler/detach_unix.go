//go:build !windows

package main

import (
	"os"
	"syscall"
)

// detachAttr detaches the child into its own session so it survives the
// parent's terminal closing.
func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}

// alive reports whether pid is a running process we could signal.
func alive(pid int) bool {
	err := syscall.Kill(pid, 0)
	return err == nil || err == syscall.EPERM
}

// lockFile takes an exclusive flock on path and keeps it until the returned
// func is called (or the process exits, which releases it too).
func lockFile(path string) func() {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return func() {}
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return func() {}
	}
	return func() { f.Close() }
}

// lockHeld reports whether another process holds the lock at path; known is
// false when there is no lock file to judge by.
func lockHeld(path string) (held, known bool) {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return false, false
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return true, true
	}
	syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
	return false, true
}

// terminate asks the process to shut down gracefully (SIGTERM lets an
// ephemeral tunnel release its domain first).
func terminate(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}
