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

package http

import (
	"net/http"
	"testing"

	"github.com/fatedier/frp/server/registry"
)

type fakeKicker struct {
	calls []string
	fail  map[string]bool // runIDs the kicker refuses (already closing)
}

func (f *fakeKicker) KickClientByRunID(runID string) bool {
	f.calls = append(f.calls, runID)
	return !f.fail[runID]
}

func registerClient(t *testing.T, r *registry.ClientRegistry, user, clientID, runID string) string {
	t.Helper()
	key, conflict := r.Register(user, clientID, runID, "", "test", "127.0.0.1:1", "v1")
	if conflict {
		t.Fatalf("register %s/%s conflicted", user, clientID)
	}
	return key
}

func TestAPIV2UserKick(t *testing.T) {
	r := registry.NewClientRegistry()
	kicker := &fakeKicker{}
	controller := NewController(nil, r, nil, kicker)
	router := newV2TestRouter(controller)

	registerClient(t, r, "alice", "c1", "run-1")
	registerClient(t, r, "alice", "c2", "run-2")
	registerClient(t, r, "bob", "b1", "run-3")

	resp := performRequestWithMethod(router, http.MethodPost, "/api/v2/users/alice/kick")
	if resp.Code != http.StatusOK {
		t.Fatalf("status mismatch, want %d got %d, body: %s", http.StatusOK, resp.Code, resp.Body.String())
	}
	envelope := decodeResponse[v2EnvelopeForTest[map[string]any]](t, resp)
	if envelope.Code != http.StatusOK {
		t.Fatalf("envelope code mismatch: %#v", envelope)
	}
	kicked, _ := envelope.Data["kicked"].([]any)
	if len(kicked) != 2 {
		t.Fatalf("want 2 kicked runIDs for alice, got %v", envelope.Data)
	}
	if len(kicker.calls) != 2 {
		t.Fatalf("kicker called %d times, want 2 (bob must be untouched): %v", len(kicker.calls), kicker.calls)
	}

	// Unknown user: still 200 with an empty list (idempotent ban loops).
	resp = performRequestWithMethod(router, http.MethodPost, "/api/v2/users/nobody/kick")
	if resp.Code != http.StatusOK {
		t.Fatalf("unknown user status mismatch, want %d got %d", http.StatusOK, resp.Code)
	}
	envelope = decodeResponse[v2EnvelopeForTest[map[string]any]](t, resp)
	if kicked, _ := envelope.Data["kicked"].([]any); len(kicked) != 0 {
		t.Fatalf("unknown user must kick nobody, got %v", envelope.Data)
	}
}

func TestAPIV2ClientKick(t *testing.T) {
	r := registry.NewClientRegistry()
	kicker := &fakeKicker{}
	controller := NewController(nil, r, nil, kicker)
	router := newV2TestRouter(controller)

	key := registerClient(t, r, "alice", "c1", "run-1")

	resp := performRequestWithMethod(router, http.MethodPost, "/api/v2/clients/"+key+"/kick")
	if resp.Code != http.StatusOK {
		t.Fatalf("status mismatch, want %d got %d, body: %s", http.StatusOK, resp.Code, resp.Body.String())
	}
	envelope := decodeResponse[v2EnvelopeForTest[map[string]any]](t, resp)
	if kicked, _ := envelope.Data["kicked"].([]any); len(kicked) != 1 {
		t.Fatalf("want the kicked runID in response, got %v", envelope.Data)
	}

	// Unknown key: 404, and the kicker is not even called.
	before := len(kicker.calls)
	resp = performRequestWithMethod(router, http.MethodPost, "/api/v2/clients/alice.missing/kick")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("unknown key status mismatch, want %d got %d", http.StatusNotFound, resp.Code)
	}
	if len(kicker.calls) != before {
		t.Fatal("kicker must not be called for an unknown key")
	}

	// Known key but the control is already closing (kick returns false): 404.
	kicker.fail = map[string]bool{"run-1": true}
	resp = performRequestWithMethod(router, http.MethodPost, "/api/v2/clients/"+key+"/kick")
	if resp.Code != http.StatusNotFound {
		t.Fatalf("losing-race status mismatch, want %d got %d", http.StatusNotFound, resp.Code)
	}
}
