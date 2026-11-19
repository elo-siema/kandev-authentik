package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/kandev/kandev/pkg/pluginsdk"
)

type fakeHost struct {
	pluginsdk.Host
	cfg map[string]any
}

func (h fakeHost) GetConfig(context.Context) (map[string]any, error) { return h.cfg, nil }

// fakeIDP is a minimal OIDC provider: the "code" it accepts at the token
// endpoint is the nonce to embed, so tests need no authorize round trip.
func fakeIDP(t *testing.T, claims map[string]any) *httptest.Server {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key},
		(&jose.SignerOptions{}).WithHeader("kid", "k"))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": srv.URL, "authorization_endpoint": srv.URL + "/authorize",
			"token_endpoint": srv.URL + "/token", "jwks_uri": srv.URL + "/jwks",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
			{Key: &key.PublicKey, KeyID: "k", Algorithm: "RS256", Use: "sig"},
		}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("code_verifier") == "" {
			http.Error(w, "missing verifier", http.StatusBadRequest)
			return
		}
		all := map[string]any{
			"iss": srv.URL, "aud": "client", "sub": "user-1", "nonce": r.FormValue("code"),
			"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
		}
		for k, v := range claims {
			all[k] = v
		}
		idToken, err := jwt.Signed(signer).Claims(all).Serialize()
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "a", "token_type": "Bearer", "id_token": idToken})
	})
	return srv
}

func newPlugin(issuer string, trust bool) *plugin {
	p := &plugin{}
	p.SetHost(fakeHost{cfg: map[string]any{
		"issuer": issuer, "client_id": "client", "client_secret": "secret",
		"kandev_url": "https://kandev.example.com/", "trust_unverified_email": trust,
	}})
	return p
}

func get(t *testing.T, p *plugin, key, query, cookie string) *pluginsdk.WebhookResponse {
	t.Helper()
	resp, err := p.HandleWebhook(context.Background(), &pluginsdk.WebhookRequest{
		WebhookKey: key, Method: http.MethodGet, Query: query, Headers: map[string]string{"Cookie": cookie},
	})
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// startLogin runs the login webhook and returns the cookie it sets plus the
// state and nonce sent to the IdP.
func startLogin(t *testing.T, p *plugin) (cookie, state, nonce string) {
	t.Helper()
	resp := get(t, p, "login", "", "")
	m := regexp.MustCompile(`document\.cookie=("[^"]*");location\.replace\(("[^"]*")\)`).FindSubmatch(resp.Body)
	if resp.Status != http.StatusOK || m == nil {
		t.Fatalf("login: %d %s", resp.Status, resp.Body)
	}
	var setCookie, target string
	_ = json.Unmarshal(m[1], &setCookie)
	_ = json.Unmarshal(m[2], &target)
	cookie, attrs, _ := strings.Cut(setCookie, ";")
	if want := " Path=/api/plugins/kandev-plugin-authentik/webhooks/callback; Max-Age=600; SameSite=Lax; Secure"; attrs != want {
		t.Errorf("cookie attrs = %q, want %q", attrs, want)
	}
	u, err := url.Parse(target)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	if q.Get("redirect_uri") != "https://kandev.example.com"+callbackPath || q.Get("code_challenge_method") != "S256" {
		t.Errorf("authorize query = %v", q)
	}
	return cookie, q.Get("state"), q.Get("nonce")
}

func assertion(t *testing.T, resp *pluginsdk.WebhookResponse) map[string]string {
	t.Helper()
	if resp.Status != http.StatusFound || resp.Headers["Location"] != "https://kandev.example.com/" {
		t.Fatalf("callback: %d %v %s", resp.Status, resp.Headers, resp.Body)
	}
	var a map[string]string
	if err := json.Unmarshal([]byte(resp.Headers["X-Kandev-Auth-Login"]), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func TestLogin(t *testing.T) {
	idp := fakeIDP(t, map[string]any{"email": "a@example.com", "email_verified": true, "name": "Ada"})
	p := newPlugin(idp.URL, false)
	cookie, state, nonce := startLogin(t, p)

	got := assertion(t, get(t, p, "callback", "code="+nonce+"&state="+state, "other=1; "+cookie))
	want := map[string]string{"provider": "authentik", "subject": "user-1", "email": "a@example.com", "display_name": "Ada"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func TestUnverifiedEmail(t *testing.T) {
	idp := fakeIDP(t, map[string]any{"email": "a@example.com", "preferred_username": "ada"})
	for trust, wantEmail := range map[bool]string{false: "", true: "a@example.com"} {
		p := newPlugin(idp.URL, trust)
		cookie, state, nonce := startLogin(t, p)
		got := assertion(t, get(t, p, "callback", "code="+nonce+"&state="+state, cookie))
		if got["email"] != wantEmail || got["display_name"] != "ada" {
			t.Errorf("trust=%v: %v", trust, got)
		}
	}
}

func TestCallbackRejects(t *testing.T) {
	idp := fakeIDP(t, map[string]any{"email": "a@example.com", "email_verified": true})
	p := newPlugin(idp.URL, false)
	cookie, state, nonce := startLogin(t, p)
	for name, tc := range map[string]struct{ query, cookie string }{
		"no cookie":      {"code=" + nonce + "&state=" + state, ""},
		"state mismatch": {"code=" + nonce + "&state=other", cookie},
		"nonce mismatch": {"code=other&state=" + state, cookie},
		"idp error":      {"error=access_denied&state=" + state, cookie},
	} {
		resp := get(t, p, "callback", tc.query, tc.cookie)
		if resp.Status < 400 || resp.Headers["X-Kandev-Auth-Login"] != "" {
			t.Errorf("%s: status %d, headers %v", name, resp.Status, resp.Headers)
		}
	}
}
