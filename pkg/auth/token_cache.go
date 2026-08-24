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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
	"github.com/fatedier/frp/pkg/util/util"
)

// tokenMaxAge bounds the freshness of the (PrivilegeKey, Timestamp) pair.
// Upstream token auth has no freshness check, so a captured pair replays
// forever; clients stamp each message with time.Now(), so this costs nothing
// in the normal flow and closes the replay window. Servers need sane clock
// sync (NTP): drift beyond this window rejects every login.
const tokenMaxAge = 15 * time.Minute

// TokenSource produces full user→raw-token snapshots. Implementations must
// be safe for concurrent use.
type TokenSource interface {
	// Fetch returns the complete current snapshot. An error means the source
	// is unhealthy; the cache keeps its previous snapshot in that case.
	Fetch() (map[string]string, error)
	// Describe names the source for logs.
	Describe() string
}

// FileTokenSource reads a JSON file mapping user to raw token. The file must
// contain raw tokens: the wire carries only the derived key
// md5(token||timestamp), which cannot be reversed, so verification needs the
// original. Protection is file permissions (0600) and edge-internal location.
type FileTokenSource struct {
	path string
}

// NewFileTokenSource reads tokens from the JSON file at path (user -> raw
// token). The file is re-read on every Fetch, so a 0600 edit lands within one
// reload interval.
func NewFileTokenSource(path string) *FileTokenSource {
	return &FileTokenSource{path: path}
}

func (s *FileTokenSource) Fetch() (map[string]string, error) {
	if fi, err := os.Stat(s.path); err == nil && runtime.GOOS != "windows" && fi.Mode().Perm()&0o077 != 0 {
		log.Warnf("token file %s is accessible by group/others (mode %v); expected 0600", s.path, fi.Mode().Perm())
	}
	buf, err := os.ReadFile(s.path)
	if err != nil {
		return nil, err
	}
	tokens := make(map[string]string)
	if err := json.Unmarshal(buf, &tokens); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	for user, token := range tokens {
		if user == "" || token == "" {
			return nil, fmt.Errorf("%s contains empty user or token entry", s.path)
		}
	}
	return tokens, nil
}

func (s *FileTokenSource) Describe() string {
	return "tokensFile " + s.path
}

// TokenCache holds the user→raw-token snapshot. The read path is a lock-cheap
// map lookup with no remote calls (NewWorkConn fires per work connection and
// must stay cheap); the write path is the reload loop below.
type TokenCache struct {
	mu          sync.RWMutex
	tokens      map[string]string
	lastRefresh time.Time

	source  TokenSource
	maxAge  time.Duration // staleness threshold for fail-close on new logins; 0 disables
	stopped chan struct{}
}

const tokenReloadInterval = 5 * time.Second

// NewTokenCache loads the first snapshot eagerly (a broken source must fail
// startup instead of silently locking every user out) and keeps refreshing in
// the background. Later reload failures keep the last good snapshot.
func NewTokenCache(source TokenSource, maxAge time.Duration) (*TokenCache, error) {
	tokens, err := source.Fetch()
	if err != nil {
		return nil, fmt.Errorf("initial token load from %s: %w", source.Describe(), err)
	}
	c := &TokenCache{
		tokens:      tokens,
		lastRefresh: time.Now(),
		source:      source,
		maxAge:      maxAge,
		stopped:     make(chan struct{}),
	}
	go c.reloadLoop()
	return c, nil
}

func (c *TokenCache) reloadLoop() {
	ticker := time.NewTicker(tokenReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-c.stopped:
			return
		case <-ticker.C:
			tokens, err := c.source.Fetch()
			if err != nil {
				log.Warnf("token reload from %s failed, keeping last snapshot: %v", c.source.Describe(), err)
				continue
			}
			c.mu.Lock()
			c.tokens = tokens
			c.lastRefresh = time.Now()
			c.mu.Unlock()
		}
	}
}

// Close stops the reload loop. It is asynchronous: it returns as soon as the
// stop signal is sent, without waiting for an in-flight Fetch to finish. The
// loop goroutine exits on its own; recreating a cache right after Close is
// safe because the old loop only touches the old cache.
func (c *TokenCache) Close() {
	select {
	case <-c.stopped:
	default:
		close(c.stopped)
	}
}

// verify recomputes the derived key with the user's token and compares in
// constant time, with a freshness window around the client timestamp.
func (c *TokenCache) verify(token, privilegeKey string, ts int64) bool {
	delta := time.Since(time.Unix(ts, 0))
	if delta > tokenMaxAge || delta < -tokenMaxAge {
		return false
	}
	return util.ConstantTimeEqString(util.GetAuthKey(token, ts), privilegeKey)
}

// MatchLogin decides new logins. A stale snapshot fails closed: while the
// source is unreachable past maxAge, no new client may get in.
func (c *TokenCache) MatchLogin(user, privilegeKey string, ts int64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.maxAge > 0 && time.Since(c.lastRefresh) > c.maxAge {
		return false
	}
	token, ok := c.tokens[user]
	return ok && c.verify(token, privilegeKey, ts)
}

// MatchAlive decides heartbeats and new work connections of established
// sessions. A stale snapshot fails open: a temporarily unreachable source
// must not drop every online user.
func (c *TokenCache) MatchAlive(user, privilegeKey string, ts int64) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if c.maxAge > 0 && time.Since(c.lastRefresh) > c.maxAge {
		return true
	}
	token, ok := c.tokens[user]
	return ok && c.verify(token, privilegeKey, ts)
}

// TokenFor returns the raw token of user. The control and work-conn crypto
// layers key off the auth token (an upstream invariant: one shared secret for
// both the derived-key handshake and channel encryption); with per-user
// tokens the server must use the login user's token so that an unmodified
// frpc, which encrypts with the token it was configured with, stays in sync.
func (c *TokenCache) TokenFor(user string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	token, ok := c.tokens[user]
	return token, ok
}

// ControlPlaneTokenSource polls the control plane's snapshot endpoint
// (GET url -> {"user": "raw token"}) - the platform-operation form of the
// token gate. The snapshot serves exactly the tokensFile shape.
type ControlPlaneTokenSource struct {
	url      string
	user     string
	password string
	maxBytes int64
	hc       *http.Client
}

// NewControlPlaneTokenSource polls the control plane's snapshot endpoint on
// every Fetch. maxBytes <= 0 defaults to 1 MiB, bounding a runaway response.
func NewControlPlaneTokenSource(url, user, password string, maxBytes int) *ControlPlaneTokenSource {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	return &ControlPlaneTokenSource{url: url, user: user, password: password,
		maxBytes: int64(maxBytes), hc: &http.Client{Timeout: 5 * time.Second}}
}

func (s *ControlPlaneTokenSource) Fetch() (map[string]string, error) {
	req, err := http.NewRequest(http.MethodGet, s.url, nil)
	if err != nil {
		return nil, err
	}
	if s.user != "" || s.password != "" {
		req.SetBasicAuth(s.user, s.password)
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, s.maxBytes))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("snapshot endpoint http %d: %s", resp.StatusCode, body)
	}
	tokens := make(map[string]string)
	if err := json.Unmarshal(body, &tokens); err != nil {
		return nil, fmt.Errorf("parse snapshot: %w", err)
	}
	for user, token := range tokens {
		if user == "" || token == "" {
			return nil, errors.New("snapshot contains empty user or token entry")
		}
	}
	return tokens, nil
}

func (s *ControlPlaneTokenSource) Describe() string { return "controlPlane " + s.url }
