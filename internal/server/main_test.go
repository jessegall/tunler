package server

import (
	"os"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// TestMain disables the artificial failed-login delay so the suite runs fast.
func TestMain(m *testing.M) {
	loginFailDelay = 0
	bcryptCost = bcrypt.MinCost
	os.Exit(m.Run())
}

func mustHash(t *testing.T, password string) string {
	t.Helper()
	h, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	return h
}
