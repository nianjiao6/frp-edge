package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/fatedier/frp/pkg/msg"
)

func newVerifyGate(url string) *VerifyGate {
	return NewVerifyGate(url, "", "", nil)
}

func verifyLoginMsg() *msg.Login { return &msg.Login{User: "xun-code", Timestamp: 1} }

func TestVerifyGateAllowLearnsToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allow":true,"token":"xun-code"}`))
	}))
	defer srv.Close()
	g := newVerifyGate(srv.URL)
	if err := g.VerifyLogin(verifyLoginMsg()); err != nil {
		t.Fatalf("allow must pass: %v", err)
	}
	if tok, ok := g.TokenFor("xun-code"); !ok || tok != "xun-code" {
		t.Fatalf("token not learned: %q ok=%v", tok, ok)
	}
}

func TestVerifyGateRefusalIsData(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allow":false,"reason":"user_banned","message":"banned"}`))
	}))
	defer srv.Close()
	g := newVerifyGate(srv.URL)
	err := g.VerifyLogin(verifyLoginMsg())
	if err == nil {
		t.Fatal("refusal must fail the login")
	}
	var ve *VerifyError
	if !errors.As(err, &ve) || ve.Reason != "user_banned" {
		t.Fatalf("refusal must carry the reason, got %v", err)
	}
}

func TestVerifyGateTransportFailures(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"401": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(401) },
		// 5xx carrying a verdict-shaped JSON body must NOT be parsed as a
		// verdict: any non-200 is a transport problem (INTERFACE.md 2.2).
		"500 with verdict body": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(500)
			_, _ = w.Write([]byte(`{"allow":false,"reason":"user_banned"}`))
		},
		"503 empty": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) },
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			err := newVerifyGate(srv.URL).VerifyLogin(verifyLoginMsg())
			if err == nil {
				t.Fatal("non-200 must fail as unreachable, not pass as a verdict")
			}
			if !errors.Is(err, errVerifyUnavailable) {
				t.Fatalf("want errVerifyUnavailable, got %v", err)
			}
		})
	}
}

func TestVerifyGateRejectsAllowWithoutToken(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"allow":true}`)) // contract violation: no token
	}))
	defer srv.Close()
	g := newVerifyGate(srv.URL)
	if err := g.VerifyLogin(verifyLoginMsg()); err == nil {
		t.Fatal("allow without the raw token must fail, not learn an empty token")
	}
	if tok, ok := g.TokenFor("xun-code"); ok || tok != "" {
		t.Fatalf("no token may be learned, got %q ok=%v", tok, ok)
	}
}
