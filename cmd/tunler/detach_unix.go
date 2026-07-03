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

// terminate asks the process to shut down gracefully (SIGTERM lets an
// ephemeral tunnel release its domain first).
func terminate(p *os.Process) error {
	return p.Signal(syscall.SIGTERM)
}
