//go:build windows

package main

import (
	"os"
	"syscall"
)

const detachedProcess = 0x00000008 // DETACHED_PROCESS

func detachAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{
		CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP | detachedProcess,
	}
}

func alive(pid int) bool {
	// FindProcess succeeds only for live processes on Windows.
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	p.Release()
	return true
}

// lockFile and lockHeld have no Windows implementation: pidfiles there are
// judged by their PID alone.
func lockFile(string) func() { return func() {} }

func lockHeld(string) (held, known bool) { return false, false }

func terminate(p *os.Process) error {
	return p.Kill()
}
