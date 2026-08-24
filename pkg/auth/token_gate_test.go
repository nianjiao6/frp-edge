// Copyright 2026 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

type staticTokenSource struct {
	tokens   map[string]string
	fetchErr error
}

func (s *staticTokenSource) Fetch() (map[string]string, error) {
	if s.fetchErr != nil {
		return nil, s.fetchErr
	}
	return s.tokens, nil
}

func (s *staticTokenSource) Describe() string { return "static" }

// setSnapshot swaps the cache snapshot directly, standing in for what the
// reload loop does after the source picks up a new table.
func setSnapshot(cache *TokenCache, tokens map[string]string) {
	cache.mu.Lock()
	defer cache.mu.Unlock()
	cache.tokens = tokens
}

func newTestGate(t *testing.T, tokens map[string]string, scopes []v1.AuthScope) *TokenGate {
	t.Helper()
	cache, err := NewTokenCache(&staticTokenSource{tokens: tokens}, 0)
	if err != nil {
		t.Fatalf("NewTokenCache: %v", err)
	}
	t.Cleanup(cache.Close)
	return NewTokenGate(cache, scopes)
}

func loginMsg(user, token string, ts int64) *msg.Login {
	return &msg.Login{
		User:         user,
		Timestamp:    ts,
		PrivilegeKey: util.GetAuthKey(token, ts),
	}
}

func TestTokenGateLoginBinding(t *testing.T) {
	gate := newTestGate(t, map[string]string{"alice": "token-a", "bob": "token-b"}, nil)

	if err := gate.VerifyLogin(loginMsg("alice", "token-a", time.Now().Unix())); err != nil {
		t.Fatalf("alice correct token rejected: %v", err)
	}
	// Alice's token presented as bob is rejected: the user field is verified
	// against the token, not free text.
	if err := gate.VerifyLogin(loginMsg("bob", "token-a", time.Now().Unix())); err == nil {
		t.Fatal("impersonation accepted")
	}
	// Unknown user and wrong token return the identical error (20j).
	errUnknown := gate.VerifyLogin(loginMsg("carol", "token-a", time.Now().Unix()))
	errWrong := gate.VerifyLogin(loginMsg("alice", "wrong", time.Now().Unix()))
	if errUnknown == nil || errWrong == nil || errUnknown.Error() != errWrong.Error() {
		t.Fatalf("error mismatch: %v vs %v", errUnknown, errWrong)
	}
}

func TestTokenGateTimestampFreshness(t *testing.T) {
	gate := newTestGate(t, map[string]string{"alice": "token-a"}, nil)

	// A captured pair older than the window is rejected even though the
	// derived key itself is valid.
	if err := gate.VerifyLogin(loginMsg("alice", "token-a", time.Now().Add(-time.Minute).Unix())); err != nil {
		t.Fatalf("fresh timestamp rejected: %v", err)
	}
	old := time.Now().Add(-2 * tokenMaxAge).Unix()
	if err := gate.VerifyLogin(loginMsg("alice", "token-a", old)); err == nil {
		t.Fatal("stale timestamp accepted")
	}
}

func TestSessionVerifierScopeGating(t *testing.T) {
	both := []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	now := time.Now().Unix()
	ping := &msg.Ping{Timestamp: now, PrivilegeKey: util.GetAuthKey("token-a", now)}
	wc := &msg.NewWorkConn{Timestamp: now, PrivilegeKey: util.GetAuthKey("token-a", now)}

	// Without scopes the gate mirrors upstream behavior: pass-through.
	gate := newTestGate(t, map[string]string{"alice": "token-a"}, nil)
	sv := gate.NewSessionVerifier("alice")
	if err := sv.VerifyPing(ping); err != nil {
		t.Fatalf("ping without HeartBeats scope should pass: %v", err)
	}

	// With scopes, a user deleted from the table fails both checks.
	gate = newTestGate(t, map[string]string{"alice": "token-a"}, both)
	sv = gate.NewSessionVerifier("alice")
	if err := sv.VerifyPing(ping); err != nil {
		t.Fatalf("live user ping rejected: %v", err)
	}
	setSnapshot(gate.tokens, map[string]string{})
	if err := sv.VerifyPing(ping); err == nil {
		t.Fatal("ping after token deletion accepted")
	}
	if err := sv.VerifyNewWorkConn(wc); err == nil {
		t.Fatal("NewWorkConn after token deletion accepted")
	}
}

func TestTokenCacheStalenessFailCloseOpen(t *testing.T) {
	src := &staticTokenSource{tokens: map[string]string{"alice": "token-a"}}
	cache, err := NewTokenCache(src, 20*time.Minute)
	if err != nil {
		t.Fatalf("NewTokenCache: %v", err)
	}
	t.Cleanup(cache.Close)
	gate := NewTokenGate(cache, nil)
	now := time.Now().Unix()

	// Force the snapshot stale, as if the control plane went unreachable.
	cache.mu.Lock()
	cache.lastRefresh = time.Now().Add(-time.Hour)
	cache.mu.Unlock()

	// New login fails closed.
	if err := gate.VerifyLogin(loginMsg("alice", "token-a", now)); err == nil {
		t.Fatal("stale snapshot admitted a new login")
	}
	// An established session fails open and still passes while the token
	// remains in the last snapshot.
	sv := gate.NewSessionVerifier("alice")
	ping := &msg.Ping{Timestamp: now, PrivilegeKey: util.GetAuthKey("token-a", now)}
	if err := sv.VerifyPing(ping); err != nil {
		t.Fatalf("stale snapshot dropped a live session: %v", err)
	}
}

func TestTokenRotationMidSession(t *testing.T) {
	both := []v1.AuthScope{v1.AuthScopeHeartBeats, v1.AuthScopeNewWorkConns}
	src := &staticTokenSource{tokens: map[string]string{"alice": "old-token"}}
	cache, err := NewTokenCache(src, 0)
	if err != nil {
		t.Fatalf("NewTokenCache: %v", err)
	}
	t.Cleanup(cache.Close)
	gate := NewTokenGate(cache, both)

	// Session established under the old token.
	sv := gate.NewSessionVerifier("alice")
	ping := func(token string) error {
		now := time.Now().Unix()
		return sv.VerifyPing(&msg.Ping{Timestamp: now, PrivilegeKey: util.GetAuthKey(token, now)})
	}
	if err := ping("old-token"); err != nil {
		t.Fatalf("ping before rotation rejected: %v", err)
	}

	// Rotate: the table now carries a new token. The next heartbeat of the
	// still-open session must fail (it is signed with the old token), and the
	// new token must pass - rotation drops old sessions at the next ping.
	setSnapshot(cache, map[string]string{"alice": "new-token"})
	if err := ping("old-token"); err == nil {
		t.Fatal("ping with old token accepted after rotation")
	}
	if err := ping("new-token"); err != nil {
		t.Fatalf("ping with new token rejected after rotation: %v", err)
	}
}

func TestFileTokenSource(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "users.json")

	if _, err := NewTokenCache(NewFileTokenSource(filepath.Join(dir, "missing.json")), 0); err == nil {
		t.Fatal("missing file must fail startup")
	}

	// Good file loads; a broken rewrite keeps the previous snapshot (20g).
	if err := os.WriteFile(path, []byte(`{"alice":"token-a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache, err := NewTokenCache(NewFileTokenSource(path), 0)
	if err != nil {
		t.Fatalf("NewTokenCache: %v", err)
	}
	t.Cleanup(cache.Close)
	if err := os.WriteFile(path, []byte(`{"alice":`), 0o600); err != nil {
		t.Fatal(err)
	}
	cache.mu.RLock()
	_, alive := cache.tokens["alice"]
	cache.mu.RUnlock()
	if !alive {
		t.Fatal("broken reload wiped the last good snapshot")
	}

	// Empty entries are rejected rather than silently disabling a user.
	if err := os.WriteFile(path, []byte(`{"alice":""}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewFileTokenSource(path).Fetch(); err == nil {
		t.Fatal("empty token entry accepted")
	}
}
