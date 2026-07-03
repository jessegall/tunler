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

func terminate(p *os.Process) error {
	return p.Kill()
}
