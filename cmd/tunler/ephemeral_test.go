package main

import (
	"testing"

	"github.com/jessegall/tunler/internal/client"
)

func TestEphemeralDomainsAreReused(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("XDG_CONFIG_HOME", "")
	store := client.Store{Hosts: map[string]client.HostCreds{}}

	first, err := pickEphemeral(&store, "h", true)
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := pickEphemeral(&store, "h", true); again != first {
		t.Fatalf("second tunnel got %q, want the remembered %q", again, first)
	}
	if saved := client.LoadStore().Hosts["h"].Ephemeral; len(saved) != 1 || saved[0] != first {
		t.Fatalf("store remembers %v, want [%s]", saved, first)
	}

	// A name held by a running local tunnel is skipped.
	writeInfo(tunnelInfo{Domain: first, Host: "h", PID: 1})
	unlock := holdTunnelLock("h", first)
	defer unlock()
	if busy, _ := pickEphemeral(&store, "h", true); busy == first {
		t.Fatal("reused a name a running tunnel holds")
	}

	forgetEphemeral(&store, "h", first, true)
	for _, d := range store.Hosts["h"].Ephemeral {
		if d == first {
			t.Fatal("forgotten name still remembered")
		}
	}
}
