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
	"errors"
	"slices"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// errAuthFailed is the single error for every TokenGate rejection: unknown
// user, wrong token and stale timestamp are indistinguishable to callers, so
// the wire leaks no user-enumeration signal.
var errAuthFailed = errors.New("authentication failed")

// TokenGate generalizes the built-in token verifier to per-user tokens: same
// message fields and derived-key protocol, but the token is looked up by the
// login user instead of one global shared secret. Mounting it is what turns
// "user" from a free-text label into a verified identity, which metering
// attribution and banning depend on.
type TokenGate struct {
	tokens               *TokenCache
	additionalAuthScopes []v1.AuthScope
}

func NewTokenGate(tokens *TokenCache, additionalAuthScopes []v1.AuthScope) *TokenGate {
	return &TokenGate{tokens: tokens, additionalAuthScopes: additionalAuthScopes}
}

// VerifyLogin checks user→token binding for a new control connection.
func (g *TokenGate) VerifyLogin(m *msg.Login) error {
	if !g.tokens.MatchLogin(m.User, m.PrivilegeKey, m.Timestamp) {
		return errAuthFailed
	}
	return nil
}

// TokenFor exposes the raw token of a user for the crypto layers, which key
// off the auth token (see TokenCache.TokenFor).
func (g *TokenGate) TokenFor(user string) (string, bool) {
	return g.tokens.TokenFor(user)
}

// NewSessionVerifier returns a standard Verifier bound to one login session.
// Ping and NewWorkConn messages carry no user field (a protocol fact), so the
// session user is captured at login time and reused for every later check:
// deleting the user from the token table fails the next heartbeat, which is
// how banning reaches already-connected clients.
func (g *TokenGate) NewSessionVerifier(user string) Verifier {
	return &sessionTokenGate{gate: g, user: user}
}

type sessionTokenGate struct {
	gate *TokenGate
	user string
}

func (s *sessionTokenGate) VerifyLogin(m *msg.Login) error {
	return s.gate.VerifyLogin(m)
}

func (s *sessionTokenGate) VerifyPing(m *msg.Ping) error {
	if !slices.Contains(s.gate.additionalAuthScopes, v1.AuthScopeHeartBeats) {
		return nil
	}
	if !s.gate.tokens.MatchAlive(s.user, m.PrivilegeKey, m.Timestamp) {
		return errAuthFailed
	}
	return nil
}

func (s *sessionTokenGate) VerifyNewWorkConn(m *msg.NewWorkConn) error {
	if !slices.Contains(s.gate.additionalAuthScopes, v1.AuthScopeNewWorkConns) {
		return nil
	}
	if !s.gate.tokens.MatchAlive(s.user, m.PrivilegeKey, m.Timestamp) {
		return errAuthFailed
	}
	return nil
}
