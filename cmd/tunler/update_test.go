package main

import (
	"strings"
	"testing"
)

func TestUpdateRefusesInsecure(t *testing.T) {
	err := cmdUpdate([]string{"--host", "tunler.example.com", "--insecure"})
	if err == nil || !strings.Contains(err.Error(), "insecure") {
		t.Fatalf("cmdUpdate --insecure = %v, want an insecure-refusal error", err)
	}
}
