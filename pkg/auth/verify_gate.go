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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/util/util"
)

// errVerifyUnavailable is returned when the verification service cannot be
// reached: new logins fail closed (never let an outage open the door), while
// established sessions keep their local re-verification below.
var errVerifyUnavailable = errors.New("verification service unreachable")

// VerifyGate authenticates by calling an external verification service on
// every login instead of holding a token snapshot (the online-verification
// form of the token gate). The service returns a structured verdict -
// user_not_found, auth_failed, user_banned, insufficient_balance, ... - and,
// when allowed, the user's raw token. The frp control-channel crypto keys
// off that token, so it is cached per user for the session lifetime.
//
// Heartbeats and new work connections are re-verified locally against the
// cached token: cheap, and independent of the verification service's
// availability (banning reaches online sessions through kick, not through
// the heartbeat, per the two-half ban design).
type VerifyGate struct {
	endpoint string
	user     string
	password string
	hc       *http.Client

	additionalAuthScopes []v1.AuthScope

	mu     sync.RWMutex
	tokens map[string]string // user -> raw token, learned at login
}

// NewVerifyGate builds the online-verification gate for one verification
// endpoint (Basic credentials optional). scopes must mirror the server's
// auth.additionalScopes: heartbeat and work-conn re-verification only fire
// for the scopes the server actually checks.
func NewVerifyGate(endpoint, user, password string, scopes []v1.AuthScope) *VerifyGate {
	return &VerifyGate{
		endpoint: endpoint, user: user, password: password,
		hc:                   &http.Client{Timeout: 5 * time.Second},
		additionalAuthScopes: scopes,
		tokens:               make(map[string]string),
	}
}

type verifyRequest struct {
	User         string `json:"user"`
	PrivilegeKey string `json:"privilegeKey"`
	Timestamp    int64  `json:"timestamp"`
	Kind         string `json:"kind"`
}

type verifyResponse struct {
	Allow   bool   `json:"allow"`
	Reason  string `json:"reason"`
	Message string `json:"message"`
	Token   string `json:"token"`
}

// VerifyError carries the structured reason of a refusal so the login reply
// can tell the client exactly why it was turned away.
type VerifyError struct {
	Reason  string
	Message string
}

func (e *VerifyError) Error() string {
	if e.Message != "" {
		return e.Message + " (" + e.Reason + ")"
	}
	return e.Reason
}

func (g *VerifyGate) call(req verifyRequest) (verifyResponse, error) {
	body, err := json.Marshal(req)
	if err != nil {
		return verifyResponse{}, err
	}
	httpReq, err := http.NewRequest(http.MethodPost, g.endpoint, bytes.NewReader(body))
	if err != nil {
		return verifyResponse{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if g.user != "" || g.password != "" {
		httpReq.SetBasicAuth(g.user, g.password)
	}
	resp, err := g.hc.Do(httpReq)
	if err != nil {
		return verifyResponse{}, errVerifyUnavailable
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return verifyResponse{}, errVerifyUnavailable
	}
	if resp.StatusCode != http.StatusOK {
		// Any non-200 - 401, 5xx, anything - is a transport problem, never
		// a verdict: per the contract a refusal travels as 200 + allow:false
		// (INTERFACE.md 2.2). Parsing a JSON body that happens to ride on an
		// error status would misread it as a verdict.
		return verifyResponse{}, errVerifyUnavailable
	}
	var out verifyResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return verifyResponse{}, errVerifyUnavailable
	}
	return out, nil
}

func (g *VerifyGate) VerifyLogin(m *msg.Login) error {
	out, err := g.call(verifyRequest{
		User: m.User, PrivilegeKey: m.PrivilegeKey, Timestamp: m.Timestamp, Kind: "login",
	})
	if err != nil {
		return err
	}
	if !out.Allow {
		return &VerifyError{Reason: out.Reason, Message: out.Message}
	}
	if out.Token == "" {
		// Contract violation by the verifier (allow without the raw token,
		// INTERFACE.md 1.2): learning an empty token would desync the
		// channel crypto at the first encrypted message - fail as
		// unreachable instead so the failure names the verifier, not the key.
		return errVerifyUnavailable
	}
	g.mu.Lock()
	g.tokens[m.User] = out.Token
	g.mu.Unlock()
	return nil
}

// TokenFor exposes the learned token for the crypto layers (see
// TokenCache.TokenFor for why the channel key follows the auth token).
func (g *VerifyGate) TokenFor(user string) (string, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	token, ok := g.tokens[user]
	return token, ok
}

// NewSessionVerifier binds later message checks to the login user. Unlike
// the snapshot-based gate, re-verification is local (cached token): the
// verification service sits on the login path only.
func (g *VerifyGate) NewSessionVerifier(user string) Verifier {
	return &sessionVerifyGate{gate: g, user: user}
}

type sessionVerifyGate struct {
	gate *VerifyGate
	user string
}

func (s *sessionVerifyGate) VerifyLogin(m *msg.Login) error {
	return s.gate.VerifyLogin(m)
}

func (s *sessionVerifyGate) VerifyPing(m *msg.Ping) error {
	if !hasScope(s.gate.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}
	if !s.localMatch(m.PrivilegeKey, m.Timestamp) {
		return errAuthFailed
	}
	return nil
}

func (s *sessionVerifyGate) VerifyNewWorkConn(m *msg.NewWorkConn) error {
	if !hasScope(s.gate.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}
	if !s.localMatch(m.PrivilegeKey, m.Timestamp) {
		return errAuthFailed
	}
	return nil
}

func (s *sessionVerifyGate) localMatch(privilegeKey string, ts int64) bool {
	token, ok := s.gate.TokenFor(s.user)
	if !ok {
		return false
	}
	delta := time.Since(time.Unix(ts, 0))
	if delta > tokenMaxAge || delta < -tokenMaxAge {
		return false
	}
	return util.ConstantTimeEqString(util.GetAuthKey(token, ts), privilegeKey)
}

func hasScope(scopes []v1.AuthScope, want v1.AuthScope) bool {
	for _, s := range scopes {
		if s == want {
			return true
		}
	}
	return false
}
