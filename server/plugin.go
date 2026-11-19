package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/kandev/kandev/pkg/pluginsdk"
	"golang.org/x/oauth2"
)

const (
	pluginID     = "kandev-plugin-authentik"
	providerID   = "authentik"
	cookieName   = "kandev_authentik_login"
	loginMaxAge  = 600 // seconds
	callbackPath = "/api/plugins/" + pluginID + "/webhooks/callback"
)

type settings struct {
	oauth                oauth2.Config
	verifier             *oidc.IDTokenVerifier
	home                 string // where the browser lands after login
	cookieAttrs          string
	trustUnverifiedEmail bool
}

type plugin struct {
	pluginsdk.UnimplementedPlugin
	mu  sync.Mutex
	cfg *settings
}

// settings is cached after the first success: Kandev restarts the plugin when
// its config changes.
func (p *plugin) settings(ctx context.Context) (*settings, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cfg != nil {
		return p.cfg, nil
	}
	host := p.Host()
	if host == nil {
		return nil, errors.New("host not connected yet")
	}
	cfg, err := host.GetConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	str := func(k string) string { s, _ := cfg[k].(string); return strings.TrimSpace(s) }
	issuer, clientID, secret := str("issuer"), str("client_id"), str("client_secret")
	base, err := url.Parse(strings.TrimSuffix(str("kandev_url"), "/"))
	if issuer == "" || clientID == "" || secret == "" || err != nil || base.Host == "" {
		return nil, errors.New("issuer, client_id, client_secret and kandev_url are required")
	}
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("discover issuer: %w", err)
	}
	redirect := base.String() + callbackPath
	attrs := fmt.Sprintf("; Path=%s; Max-Age=%d; SameSite=Lax", base.Path+callbackPath, loginMaxAge)
	if base.Scheme == "https" {
		attrs += "; Secure"
	}
	trust, _ := cfg["trust_unverified_email"].(bool)
	p.cfg = &settings{
		oauth: oauth2.Config{
			ClientID: clientID, ClientSecret: secret, Endpoint: provider.Endpoint(),
			RedirectURL: redirect, Scopes: []string{oidc.ScopeOpenID, "email", "profile"},
		},
		verifier:             provider.Verifier(&oidc.Config{ClientID: clientID}),
		home:                 base.String() + "/",
		cookieAttrs:          attrs,
		trustUnverifiedEmail: trust,
	}
	return p.cfg, nil
}

func (p *plugin) HandleWebhook(ctx context.Context, req *pluginsdk.WebhookRequest) (*pluginsdk.WebhookResponse, error) {
	if req.Method != http.MethodGet {
		return text(http.StatusMethodNotAllowed, "method not allowed"), nil
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	s, err := p.settings(ctx)
	if err != nil {
		log.Printf("authentik: %v", err)
		return text(http.StatusServiceUnavailable, "Authentik SSO is not configured correctly; see the Kandev logs."), nil
	}
	switch req.WebhookKey {
	case "login":
		return s.login(), nil
	case "callback":
		return s.callback(ctx, req), nil
	}
	return text(http.StatusNotFound, "not found"), nil
}

// login binds the flow to this browser and redirects to Authentik. Kandev
// drops Set-Cookie from plugin responses, so the state/PKCE/nonce cookie is set
// by a script instead; it only ever needs to be read back by callback.
func (s *settings) login() *pluginsdk.WebhookResponse {
	state, verifier, nonce := oauth2.GenerateVerifier(), oauth2.GenerateVerifier(), oauth2.GenerateVerifier()
	authURL := s.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier))
	// json.Marshal escapes <, > and &, so the values are safe inside <script>.
	cookie, _ := json.Marshal(cookieName + "=" + state + "." + verifier + "." + nonce + s.cookieAttrs)
	target, _ := json.Marshal(authURL)
	return &pluginsdk.WebhookResponse{
		Status:  http.StatusOK,
		Headers: map[string]string{"Content-Type": "text/html; charset=utf-8", "Cache-Control": "no-store"},
		Body:    fmt.Appendf(nil, "<!doctype html><title>Redirecting…</title><script>document.cookie=%s;location.replace(%s)</script>", cookie, target),
	}
}

func (s *settings) callback(ctx context.Context, req *pluginsdk.WebhookRequest) *pluginsdk.WebhookResponse {
	q, _ := url.ParseQuery(req.Query)
	if e := q.Get("error"); e != "" {
		return text(http.StatusBadRequest, "Authentik login failed: "+e)
	}
	parts := strings.Split(loginCookie(req.Headers), ".")
	if len(parts) != 3 || q.Get("code") == "" ||
		subtle.ConstantTimeCompare([]byte(parts[0]), []byte(q.Get("state"))) != 1 {
		return text(http.StatusBadRequest, "Login expired or was started in another browser. Please try again.")
	}
	token, err := s.oauth.Exchange(ctx, q.Get("code"), oauth2.VerifierOption(parts[1]))
	if err != nil {
		return failed("code exchange", err)
	}
	raw, _ := token.Extra("id_token").(string)
	idToken, err := s.verifier.Verify(ctx, raw)
	if err != nil {
		return failed("id token", err)
	}
	if subtle.ConstantTimeCompare([]byte(idToken.Nonce), []byte(parts[2])) != 1 {
		return failed("id token", errors.New("nonce mismatch"))
	}
	var claims struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
		Username      string `json:"preferred_username"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return failed("id token claims", err)
	}
	// Kandev links accounts by email, so an email the IdP has not verified must
	// not be asserted. Without one, only already-linked identities can log in.
	if !claims.EmailVerified && !s.trustUnverifiedEmail {
		claims.Email = ""
	}
	if claims.Name == "" {
		claims.Name = claims.Username
	}
	assertion, _ := json.Marshal(map[string]string{
		"provider": providerID, "subject": idToken.Subject,
		"email": claims.Email, "display_name": claims.Name,
	})
	return &pluginsdk.WebhookResponse{
		Status: http.StatusFound,
		Headers: map[string]string{
			"Location": s.home, "Cache-Control": "no-store",
			"X-Kandev-Auth-Login": string(assertion),
		},
	}
}

func loginCookie(headers map[string]string) string {
	for k, v := range headers {
		if !strings.EqualFold(k, "Cookie") {
			continue
		}
		cookies, _ := http.ParseCookie(v)
		for _, c := range cookies {
			if c.Name == cookieName {
				return c.Value
			}
		}
	}
	return ""
}

func failed(step string, err error) *pluginsdk.WebhookResponse {
	log.Printf("authentik: %s: %v", step, err)
	return text(http.StatusBadGateway, "Authentik login failed; see the Kandev logs.")
}

func text(status int32, msg string) *pluginsdk.WebhookResponse {
	return &pluginsdk.WebhookResponse{
		Status:  status,
		Headers: map[string]string{"Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store"},
		Body:    []byte(msg),
	}
}
