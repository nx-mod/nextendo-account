package main

// Local "open" mode, for a private stack (LAN / ZeroTier) where the consoles and
// emulators carry accounts that were made elsewhere.
//
// A console's NSA id is derived from the account service that linked it
// (deriveID("baas", pid), keyed by that service's session secret), so an account
// made on another deployment can never resolve here. With NEXTENDO_LOCAL_OPEN=1:
//
//   - an NSA id nobody owns yet gets an account created for it on first sight, so
//     the game servers can give the console a stable PID and report its presence;
//   - every account is a friend of every other one (blocks are respected), so
//     presence and friend lists work without anyone adding anyone.
//
// Never enable this on a public deployment: it turns /api/nsa into open
// registration and removes friend consent.

import (
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/crypto/bcrypt"
	"log"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

var localOpen = os.Getenv("NEXTENDO_LOCAL_OPEN") == "1"

// localOpenMaxAccounts bounds auto-created accounts: /api/nsa is reachable by
// anything that can reach this service, and each unknown id would add a row.
const localOpenMaxAccounts = 256

// localOpenPIDSpan bounds the PIDs EnsurePID will create: firstNexPID up to this many above it.
const localOpenPIDSpan uint64 = 100_000_000

// EnsureBaasNSA returns the account owning nsa, creating it if none does.
func (s *jsonStore) EnsureBaasNSA(nsa uint64) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	baas := fmt.Sprintf("%016x", nsa)
	for _, a := range s.Accts {
		have := a.BaasID
		if have == "" {
			have = deriveID(sessionSecret, "baas", a.PID)
		}
		if strings.EqualFold(have, baas) {
			return a, nil
		}
	}
	if len(s.Accts) >= localOpenMaxAccounts {
		return nil, fmt.Errorf("local open mode: account limit (%d) reached", localOpenMaxAccounts)
	}

	a := &Account{
		ID:            s.NextID,
		Username:      fmt.Sprintf("player-%04x", nsa&0xffff),
		Email:         fmt.Sprintf("nsa-%s@local.invalid", baas),
		PasswordHash:  "!", // never matches a password hash: this account has no web login
		PID:           s.NextP,
		FriendCode:    genFriendCode(),
		CreatedAt:     time.Now().UTC(),
		EmailVerified: true,
		BaasID:        baas,
	}
	a.ensureNintendoIDs()
	s.Accts[a.ID] = a
	s.byUser[strings.ToLower(a.Username)] = a.ID
	s.byMail[strings.ToLower(a.Email)] = a.ID
	s.byPID[a.PID] = a.ID
	s.byCode[a.FriendCode] = a.ID
	s.NextID++
	s.NextP++
	s.befriendAllLocked()
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

// BindBaasNSA makes baas (a console's BaaS user id, 16 hex digits) the NSA id of the account with this PID:
// a console that links or imports that account's Nintendo Account keeps the user it registered, and
// /api/nsa, the game servers and nnex then all resolve that user to this account. An account created
// earlier for the same id by EnsureBaasNSA goes back to its derived id.
func (s *jsonStore) BindBaasNSA(pid uint64, baas string) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	id, ok := s.byPID[pid]
	if !ok {
		return nil, ErrNotFound
	}
	a := s.Accts[id]
	baas = strings.ToLower(baas)
	for _, o := range s.Accts {
		if o != a && strings.EqualFold(o.BaasID, baas) {
			o.BaasID = deriveID(sessionSecret, "baas", o.PID)
		}
	}
	a.BaasID = baas
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

// POST /internal/baas-link {"pid":N,"baas":"<16 hex>"} (local open mode, internal key): see BindBaasNSA.
// baas-jwks calls it when a console federates a Nintendo Account.
func (s *server) internalBaasLink(w http.ResponseWriter, r *http.Request) {
	if !localOpen {
		http.NotFound(w, r)
		return
	}
	if k := os.Getenv("NEXTENDO_INTERNAL_KEY"); k != "" && r.Header.Get("X-Internal-Key") != k {
		writeErr(w, http.StatusUnauthorized, "interne")
		return
	}
	var in struct {
		PID  uint64 `json:"pid"`
		Baas string `json:"baas"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || len(in.Baas) != 16 {
		writeErr(w, http.StatusBadRequest, "pid/baas")
		return
	}
	if _, err := strconv.ParseUint(in.Baas, 16, 64); err != nil {
		writeErr(w, http.StatusBadRequest, "baas")
		return
	}
	res, ok := s.store.(interface {
		BindBaasNSA(uint64, string) (*Account, error)
	})
	if !ok {
		http.NotFound(w, r)
		return
	}
	a, err := res.BindBaasNSA(in.PID, in.Baas)
	if err != nil {
		writeErr(w, http.StatusNotFound, "compte introuvable")
		return
	}
	log.Printf("[local-open] pid=%d now owns BaaS user %s", a.PID, a.BaasID)
	writeJSON(w, http.StatusOK, map[string]any{"pid": a.PID, "name": displayName(a)})
}

// EnsurePID returns the account with this PID, creating it if there is none. Local open mode
// only: the PID of a player whose real account lives on another deployment (Citron sends it on
// its own) reaches /internal/online-check directly, without ever asking /api/nsa, so nothing
// else would create the account and the online gate would refuse it as "unknown".
// Only PIDs in the Nextendo range are accepted, and the same account limit applies.
func (s *jsonStore) EnsurePID(pid uint64) (*Account, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if id, ok := s.byPID[pid]; ok {
		return s.Accts[id], nil
	}
	if pid < firstNexPID || pid >= firstNexPID+localOpenPIDSpan {
		return nil, fmt.Errorf("pid %d is outside the Nextendo range", pid)
	}
	if len(s.Accts) >= localOpenMaxAccounts {
		return nil, fmt.Errorf("local open mode: account limit (%d) reached", localOpenMaxAccounts)
	}

	a := &Account{
		ID:            s.NextID,
		Username:      fmt.Sprintf("player-%04d", pid%10000),
		Email:         fmt.Sprintf("pid-%d@local.invalid", pid),
		PasswordHash:  "!", // no web login for an account made this way
		PID:           pid,
		FriendCode:    genFriendCode(),
		CreatedAt:     time.Now().UTC(),
		EmailVerified: true,
	}
	a.ensureNintendoIDs()
	s.Accts[a.ID] = a
	s.byUser[strings.ToLower(a.Username)] = a.ID
	s.byMail[strings.ToLower(a.Email)] = a.ID
	s.byPID[a.PID] = a.ID
	s.byCode[a.FriendCode] = a.ID
	s.NextID++
	if pid >= s.NextP {
		s.NextP = pid + 1 // never hand this PID out again
	}
	s.befriendAllLocked()
	if err := s.persist(); err != nil {
		return nil, err
	}
	return a, nil
}

// befriendAllLocked makes every pair of accounts mutual friends unless either has
// blocked the other, and drops pending requests (there is nothing left to accept).
// The caller holds s.mu. Reports whether anything changed.
func (s *jsonStore) befriendAllLocked() bool {
	pids := make([]uint64, 0, len(s.Accts))
	for _, a := range s.Accts {
		pids = append(pids, a.PID)
	}
	sort.Slice(pids, func(i, j int) bool { return pids[i] < pids[j] })

	blocks := func(a *Account, pid uint64) bool {
		for _, b := range a.Blocked {
			if b == pid {
				return true
			}
		}
		return false
	}

	changed := false
	for _, a := range s.Accts {
		want := make([]uint64, 0, len(pids))
		for _, pid := range pids {
			if pid == a.PID || blocks(a, pid) {
				continue
			}
			if o, ok := s.byPID[pid]; ok && blocks(s.Accts[o], a.PID) {
				continue
			}
			want = append(want, pid)
		}
		if !equalPIDs(a.Friends, want) {
			a.Friends = want
			changed = true
		}
		if len(a.FriendRequests) > 0 {
			a.FriendRequests = nil
			changed = true
		}
	}
	return changed
}

func equalPIDs(a, b []uint64) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// openUsername turns an e-mail into a display name for an account made by openLoginCreate:
// the part before the @, reduced to letters, digits, "_" and "-", at most 16 characters.
func openUsername(email string) string {
	local := email
	if i := strings.IndexByte(email, '@'); i >= 0 {
		local = email[:i]
	}
	var b strings.Builder
	for _, r := range local {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_' || r == '-' {
			b.WriteRune(r)
		}
		if b.Len() == 16 {
			break
		}
	}
	if b.Len() < 3 {
		return "player-" + b.String()
	}
	return b.String()
}

// openLoginCreate makes the account for an e-mail that has none yet, so in local open mode any
// e-mail and password signs in: the first login creates the account with that password, and
// later logins must present the same one. The caller only gets here for ErrNotFound; an
// existing e-mail with a wrong password is still refused.
func openLoginCreate(store Store, email, password string) (*Account, error) {
	if password == "" {
		return nil, errors.New("empty password")
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	return store.Create(openUsername(email), email, string(hash))
}
