//go:build !windows

package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestControlPlaneTokenSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || user != "op" || pass != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Path == "/internal/tokens" {
			_, _ = w.Write([]byte(`{"alice": "tok-a", "bob": "tok-b"}`))
			return
		}
		if r.URL.Path == "/internal/broken" {
			_, _ = w.Write([]byte(`{"alice":`)) // truncated JSON
			return
		}
		if r.URL.Path == "/internal/empty-entry" {
			_, _ = w.Write([]byte(`{"alice": ""}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	ok := func(path string) *ControlPlaneTokenSource {
		return NewControlPlaneTokenSource(srv.URL+path, "op", "secret", 0)
	}

	tokens, err := ok("/internal/tokens").Fetch()
	if err != nil || len(tokens) != 2 || tokens["alice"] != "tok-a" {
		t.Fatalf("good snapshot: %v %v", tokens, err)
	}
	if _, err := NewControlPlaneTokenSource(srv.URL+"/internal/tokens", "op", "wrong", 0).Fetch(); err == nil {
		t.Fatal("bad credentials must fail")
	}
	if _, err := ok("/internal/broken").Fetch(); err == nil {
		t.Fatal("truncated JSON must fail (cache keeps last snapshot)")
	}
	if _, err := ok("/internal/empty-entry").Fetch(); err == nil {
		t.Fatal("empty token entry must fail")
	}
	if _, err := ok("/no/such").Fetch(); err == nil {
		t.Fatal("404 must fail")
	}
}
