package main

import (
	"path/filepath"
	"testing"

	"golang.org/x/crypto/bcrypt"
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

func TestEnsurePIDCreatesOnceAndKeepsCounterAhead(t *testing.T) {
	s := newTestOpenStore(t)
	other, _ := s.EnsureBaasNSA(7)

	a, err := s.EnsurePID(1800029871)
	if err != nil {
		t.Fatal(err)
	}
	if a.PID != 1800029871 || !a.EmailVerified {
		t.Fatalf("unexpected account: %+v", a)
	}
	again, err := s.EnsurePID(1800029871)
	if err != nil || again.ID != a.ID {
		t.Fatalf("the same PID must return the same account: %v %v", again, err)
	}
	if got, err := s.ByPID(1800029871); err != nil || got.ID != a.ID {
		t.Fatalf("ByPID must find it: %v %v", got, err)
	}
	// never handed out again by the counter
	next, _ := s.EnsureBaasNSA(8)
	if next.PID <= 1800029871 {
		t.Fatalf("counter must move past the created PID, got %d", next.PID)
	}
	// friends with everyone
	other, _ = s.ByPID(other.PID)
	if !containsPID(other.Friends, a.PID) || !containsPID(a.Friends, other.PID) {
		t.Fatalf("expected mutual friends: other=%v a=%v", other.Friends, a.Friends)
	}
}

func TestEnsurePIDRefusesOutOfRangeAndOverLimit(t *testing.T) {
	s := newTestOpenStore(t)
	for _, bad := range []uint64{0, 1, firstNexPID - 1, firstNexPID + localOpenPIDSpan} {
		if _, err := s.EnsurePID(bad); err == nil {
			t.Fatalf("pid %d is outside the Nextendo range and must be refused", bad)
		}
	}
	for i := 1; i <= localOpenMaxAccounts; i++ {
		if _, err := s.EnsureBaasNSA(uint64(i)); err != nil {
			t.Fatalf("account %d: %v", i, err)
		}
	}
	if _, err := s.EnsurePID(firstNexPID + 50_000_000); err == nil {
		t.Fatal("the account limit must apply to EnsurePID too")
	}
}

func containsPID(list []uint64, pid uint64) bool {
	for _, p := range list {
		if p == pid {
			return true
		}
	}
	return false
}

func TestOpenUsername(t *testing.T) {
	cases := map[string]string{
		"john@example.com":                "john",
		"John.Doe+tag@example.com":        "JohnDoetag",
		"a@example.com":                   "player-a",
		"@example.com":                    "player-",
		"averyveryverylongusername@x.com": "averyveryverylon",
		"_-_@x.com":                       "_-_",
	}
	for in, want := range cases {
		if got := openUsername(in); got != want {
			t.Errorf("openUsername(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOpenLoginCreateMakesTheAccountAndKeepsThePassword(t *testing.T) {
	// only ever reached in open mode, where Create marks new accounts e-mail verified
	prev := localOpen
	localOpen = true
	defer func() { localOpen = prev }()

	s := newTestOpenStore(t)
	a, err := openLoginCreate(s, "new.player@example.com", "pw")
	if err != nil {
		t.Fatal(err)
	}
	if a.Email != "new.player@example.com" || !a.EmailVerified {
		t.Fatalf("unexpected account: %+v", a)
	}
	if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte("pw")) != nil {
		t.Fatal("the account must keep the password it was created with")
	}
	if bcrypt.CompareHashAndPassword([]byte(a.PasswordHash), []byte("other")) == nil {
		t.Fatal("a different password must not match")
	}
	if _, err := openLoginCreate(s, "x@example.com", ""); err == nil {
		t.Fatal("an empty password must be refused")
	}
	if _, err := openLoginCreate(s, "new.player@example.com", "pw2"); err == nil {
		t.Fatal("creating the same e-mail twice must fail, not overwrite the password")
	}
}

func TestOpenModePasswordPolicy(t *testing.T) {
	prev := localOpen
	localOpen = true
	defer func() { localOpen = prev }()

	if msg := validatePassword("a"); msg != "" {
		t.Fatalf("open mode must accept any non-empty password, got %q", msg)
	}
	if msg := validatePassword(""); msg == "" {
		t.Fatal("an empty password is still refused")
	}
}

func TestStrictPasswordPolicyStillAppliesWhenOpenModeIsOff(t *testing.T) {
	prev := localOpen
	localOpen = false
	defer func() { localOpen = prev }()

	if msg := validatePassword("a"); msg == "" {
		t.Fatal("off by default: a one-character password must still be refused")
	}
	if msg := validatePassword("Correct-Horse-9!"); msg != "" {
		t.Fatalf("a strong password must pass, got %q", msg)
	}
}
