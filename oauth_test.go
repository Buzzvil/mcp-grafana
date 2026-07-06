package mcpgrafana

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// newTokenServer returns an httptest server that implements the OAuth2
// client-credentials token endpoint, handing out sequentially-numbered tokens
// and counting how many times it was called.
func newTokenServer(t *testing.T) (*httptest.Server, *int32) {
	t.Helper()
	var calls int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&calls, 1)
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "client_credentials", r.PostFormValue("grant_type"))
		w.Header().Set("Content-Type", "application/json")
		// A long-lived token so the source caches it and doesn't refetch.
		_, _ = w.Write([]byte(`{"access_token":"tok-` +
			string(rune('0'+n)) + `","token_type":"Bearer","expires_in":3600}`))
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestOAuthConfigEnabled(t *testing.T) {
	t.Run("nil config is not enabled", func(t *testing.T) {
		var c *OAuthConfig
		assert.False(t, c.Enabled())
	})

	t.Run("requires client id, secret and token url", func(t *testing.T) {
		assert.False(t, (&OAuthConfig{}).Enabled())
		assert.False(t, (&OAuthConfig{ClientID: "id"}).Enabled())
		assert.False(t, (&OAuthConfig{ClientID: "id", ClientSecret: "secret"}).Enabled())
		assert.True(t, (&OAuthConfig{ClientID: "id", ClientSecret: "secret", TokenURL: "https://x/token"}).Enabled())
	})
}

func TestParseOAuthScopes(t *testing.T) {
	assert.Nil(t, parseOAuthScopes(""))
	assert.Nil(t, parseOAuthScopes("   "))
	assert.Equal(t, []string{"a"}, parseOAuthScopes("a"))
	assert.Equal(t, []string{"a", "b", "c"}, parseOAuthScopes("a b c"))
	assert.Equal(t, []string{"a", "b", "c"}, parseOAuthScopes("a,b,c"))
	assert.Equal(t, []string{"a", "b", "c"}, parseOAuthScopes(" a, b ,c "))
}

func TestBuildOAuthConfigFromEnv(t *testing.T) {
	logger := discardLogger()

	t.Run("returns nil when nothing configured", func(t *testing.T) {
		t.Setenv(grafanaOAuthClientIDEnvVar, "")
		t.Setenv(grafanaOAuthClientSecretEnvVar, "")
		t.Setenv(grafanaOAuthTokenURLEnvVar, "")
		assert.Nil(t, buildOAuthConfigFromEnv(logger))
	})

	t.Run("returns nil and warns when incomplete", func(t *testing.T) {
		t.Setenv(grafanaOAuthClientIDEnvVar, "id")
		t.Setenv(grafanaOAuthClientSecretEnvVar, "")
		t.Setenv(grafanaOAuthTokenURLEnvVar, "")
		assert.Nil(t, buildOAuthConfigFromEnv(logger))
	})

	t.Run("builds full config with scopes and audience", func(t *testing.T) {
		t.Setenv(grafanaOAuthClientIDEnvVar, "my-id")
		t.Setenv(grafanaOAuthClientSecretEnvVar, "my-secret")
		t.Setenv(grafanaOAuthTokenURLEnvVar, "https://issuer/oauth/token")
		t.Setenv(grafanaOAuthScopesEnvVar, "profile,metrics:read")
		t.Setenv(grafanaOAuthAudienceEnvVar, "grafana")

		cfg := buildOAuthConfigFromEnv(logger)
		require.NotNil(t, cfg)
		assert.True(t, cfg.Enabled())
		assert.Equal(t, "my-id", cfg.ClientID)
		assert.Equal(t, "my-secret", cfg.ClientSecret)
		assert.Equal(t, "https://issuer/oauth/token", cfg.TokenURL)
		assert.Equal(t, []string{"profile", "metrics:read"}, cfg.Scopes)
		assert.Equal(t, url.Values{"audience": {"grafana"}}, cfg.EndpointParams)
	})
}

func TestOAuthConfigToken(t *testing.T) {
	t.Run("returns error when not enabled", func(t *testing.T) {
		_, err := (&OAuthConfig{}).Token()
		require.Error(t, err)
	})

	t.Run("fetches and caches the token", func(t *testing.T) {
		srv, calls := newTokenServer(t)
		cfg := &OAuthConfig{
			ClientID:     "id",
			ClientSecret: "secret",
			TokenURL:     srv.URL,
		}

		tok, err := cfg.Token()
		require.NoError(t, err)
		assert.Equal(t, "tok-1", tok.AccessToken)

		// Second call should reuse the still-valid cached token.
		tok2, err := cfg.Token()
		require.NoError(t, err)
		assert.Equal(t, "tok-1", tok2.AccessToken)
		assert.Equal(t, int32(1), atomic.LoadInt32(calls), "token endpoint should be hit only once")
	})
}

func TestAuthRoundTripperOAuth(t *testing.T) {
	newMock := func(captured **http.Request) *capturingMockRT {
		return &capturingMockRT{fn: func(req *http.Request) (*http.Response, error) {
			*captured = req
			return &http.Response{StatusCode: 200}, nil
		}}
	}

	t.Run("sets bearer token from oauth token source", func(t *testing.T) {
		srv, _ := newTokenServer(t)
		var captured *http.Request
		rt := NewAuthRoundTripper(newMock(&captured), "", "", "", nil)
		rt.oauth = &OAuthConfig{ClientID: "id", ClientSecret: "secret", TokenURL: srv.URL}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, "Bearer tok-1", captured.Header.Get("Authorization"))
	})

	t.Run("oauth takes precedence over static api key", func(t *testing.T) {
		srv, _ := newTokenServer(t)
		var captured *http.Request
		rt := NewAuthRoundTripper(newMock(&captured), "", "", "static-key", nil)
		rt.oauth = &OAuthConfig{ClientID: "id", ClientSecret: "secret", TokenURL: srv.URL}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, "Bearer tok-1", captured.Header.Get("Authorization"))
	})

	t.Run("obo tokens take precedence over oauth", func(t *testing.T) {
		srv, calls := newTokenServer(t)
		var captured *http.Request
		rt := NewAuthRoundTripper(newMock(&captured), "access-tok", "id-tok", "", nil)
		rt.oauth = &OAuthConfig{ClientID: "id", ClientSecret: "secret", TokenURL: srv.URL}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", captured.Header.Get("X-Access-Token"))
		assert.Equal(t, "id-tok", captured.Header.Get("X-Grafana-Id"))
		assert.Empty(t, captured.Header.Get("Authorization"))
		assert.Equal(t, int32(0), atomic.LoadInt32(calls), "OAuth token endpoint should not be called when OBO wins")
	})

	t.Run("oauth from context enables auth for transports built without it", func(t *testing.T) {
		srv, _ := newTokenServer(t)
		var captured *http.Request
		// Transport built with no OAuth baked in...
		rt := NewAuthRoundTripper(newMock(&captured), "", "", "", nil)

		// ...but the request context carries an enabled OAuth config.
		ctx := WithGrafanaConfig(context.Background(), GrafanaConfig{
			OAuth: &OAuthConfig{ClientID: "id", ClientSecret: "secret", TokenURL: srv.URL},
		})
		req, _ := http.NewRequestWithContext(ctx, "GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, "Bearer tok-1", captured.Header.Get("Authorization"))
	})

	t.Run("propagates token fetch errors", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "nope", http.StatusUnauthorized)
		}))
		t.Cleanup(srv.Close)
		var captured *http.Request
		rt := NewAuthRoundTripper(newMock(&captured), "", "", "", nil)
		rt.oauth = &OAuthConfig{ClientID: "id", ClientSecret: "secret", TokenURL: srv.URL}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.Error(t, err)
		assert.Nil(t, captured, "underlying transport should not be reached when token fetch fails")
	})
}
