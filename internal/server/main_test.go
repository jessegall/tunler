package server

import (
	"os"
	"testing"
)

// TestMain disables the artificial failed-login delay so the suite runs fast.
func TestMain(m *testing.M) {
	loginFailDelay = 0
	os.Exit(m.Run())
}
