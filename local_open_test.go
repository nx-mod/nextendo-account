package main

import (
	"path/filepath"
	"testing"
)

func newTestOpenStore(t *testing.T) *jsonStore {
	t.Helper()
	sessionSecret = []byte("test-secret")
	s, err := newJSONStore(filepath.Join(t.TempDir(), "accounts.json"))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestEnsureBaasNSACreatesOnceAndBefriendsEveryone(t *testing.T) {
	s := newTestOpenStore(t)

	a, err := s.EnsureBaasNSA(0x1111222233334444)
	if err != nil {
		t.Fatal(err)
	}
	again, err := s.EnsureBaasNSA(0x1111222233334444)
	if err != nil || again.PID != a.PID {
		t.Fatalf("same NSA id must map to the same account: %v %v", again, err)
	}
	b, err := s.EnsureBaasNSA(0x5555666677778888)
	if err != nil {
		t.Fatal(err)
	}
	if a.PID == b.PID {
		t.Fatal("distinct NSA ids must get distinct accounts")
	}
	if found, err := s.ByBaasNSA(0x1111222233334444); err != nil || found.PID != a.PID {
		t.Fatalf("ByBaasNSA must find the auto-created account: %v %v", found, err)
	}

	// re-read: a.Friends was set when b was created
	a, _ = s.ByPID(a.PID)
	if !equalPIDs(a.Friends, []uint64{b.PID}) || !equalPIDs(b.Friends, []uint64{a.PID}) {
		t.Fatalf("expected mutual friends, got a=%v b=%v", a.Friends, b.Friends)
	}
}

func TestBefriendAllRespectsBlocksAndClearsRequests(t *testing.T) {
	s := newTestOpenStore(t)
	a, _ := s.EnsureBaasNSA(1)
	b, _ := s.EnsureBaasNSA(2)
	c, _ := s.EnsureBaasNSA(3)

	s.mu.Lock()
	a.Blocked = []uint64{b.PID}
	c.FriendRequests = []uint64{a.PID}
	s.befriendAllLocked()
	s.mu.Unlock()

	if !equalPIDs(a.Friends, []uint64{c.PID}) {
		t.Fatalf("a blocked b, so a must only have c: %v", a.Friends)
	}
	if !equalPIDs(b.Friends, []uint64{c.PID}) {
		t.Fatalf("b is blocked by a, so b must only have c: %v", b.Friends)
	}
	if len(c.FriendRequests) != 0 {
		t.Fatalf("pending requests must be dropped: %v", c.FriendRequests)
	}
}

func TestEnsureBaasNSAHonoursAccountLimit(t *testing.T) {
	s := newTestOpenStore(t)
	for i := 1; i <= localOpenMaxAccounts; i++ {
		if _, err := s.EnsureBaasNSA(uint64(i)); err != nil {
			t.Fatalf("account %d: %v", i, err)
		}
	}
	if _, err := s.EnsureBaasNSA(uint64(localOpenMaxAccounts) + 1); err == nil {
		t.Fatal("expected the account limit to refuse a new id")
	}
	// an id that already has an account still resolves at the limit
	if _, err := s.EnsureBaasNSA(1); err != nil {
		t.Fatalf("existing id must keep resolving at the limit: %v", err)
	}
}
