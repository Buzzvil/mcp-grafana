package mcpgrafana

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

// fakeIdP is a minimal OAuth2 identity provider implementing the Device
// Authorization Grant (RFC 8628) and refresh_token grants, for exercising the
// login flow end to end without a real browser or IdP.
type fakeIdP struct {
	srv         *httptest.Server
	mu          sync.Mutex
	approved    bool
	deviceCalls int
	pollCalls   int
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	idp := &fakeIdP{}
	mux := http.NewServeMux()

	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.PostFormValue("client_id") == "" {
			http.Error(w, "missing client_id", http.StatusBadRequest)
			return
		}
		idp.mu.Lock()
		idp.deviceCalls++
		idp.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"device_code":"dev-code-123","user_code":"WXYZ-1234",`+
			`"verification_uri":%q,"verification_uri_complete":%q,"expires_in":600,"interval":1}`,
			idp.srv.URL+"/device/verify", idp.srv.URL+"/device/verify?code=WXYZ-1234")
	})

	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.PostFormValue("grant_type") {
		case "urn:ietf:params:oauth:grant-type:device_code":
			idp.mu.Lock()
			idp.pollCalls++
			approved := idp.approved
			idp.mu.Unlock()
			if !approved {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusBadRequest)
				_, _ = fmt.Fprint(w, `{"error":"authorization_pending"}`)
				return
			}
			writeTokenResponse(w, "access-1", "refresh-1", 3600)
		case "refresh_token":
			if r.PostFormValue("refresh_token") == "" {
				http.Error(w, "missing refresh_token", http.StatusBadRequest)
				return
			}
			writeTokenResponse(w, "access-refreshed", "refresh-2", 3600)
		default:
			http.Error(w, "unsupported grant_type", http.StatusBadRequest)
		}
	})

	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	return idp
}

func (idp *fakeIdP) approve() {
	idp.mu.Lock()
	idp.approved = true
	idp.mu.Unlock()
}

func (idp *fakeIdP) deviceCallCount() int {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	return idp.deviceCalls
}

func (idp *fakeIdP) deviceAuthURL() string { return idp.srv.URL + "/device" }
func (idp *fakeIdP) tokenURL() string      { return idp.srv.URL + "/token" }

func writeTokenResponse(w http.ResponseWriter, access, refresh string, expiresIn int) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","refresh_token":%q,"expires_in":%d}`,
		access, refresh, expiresIn)
}

func writeTokenFile(t *testing.T, path string, tok *oauth2.Token) {
	t.Helper()
	data, err := json.Marshal(tok)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, data, 0o600))
}

func TestOAuthConfigEnabled(t *testing.T) {
	var nilCfg *OAuthConfig
	assert.False(t, nilCfg.Enabled())
	assert.False(t, (&OAuthConfig{}).Enabled())
	assert.False(t, (&OAuthConfig{ClientID: "id"}).Enabled())
	assert.False(t, (&OAuthConfig{ClientID: "id", DeviceAuthURL: "https://x/device"}).Enabled())
	assert.True(t, (&OAuthConfig{ClientID: "id", DeviceAuthURL: "https://x/device", TokenURL: "https://x/token"}).Enabled())
}

func TestParseOAuthScopes(t *testing.T) {
	assert.Nil(t, parseOAuthScopes(""))
	assert.Nil(t, parseOAuthScopes("   "))
	assert.Equal(t, []string{"openid"}, parseOAuthScopes("openid"))
	assert.Equal(t, []string{"openid", "profile", "email"}, parseOAuthScopes("openid profile email"))
	assert.Equal(t, []string{"openid", "profile", "email"}, parseOAuthScopes("openid,profile,email"))
	assert.Equal(t, []string{"openid", "profile"}, parseOAuthScopes(" openid , profile "))
}

func TestBuildOAuthConfigFromEnv(t *testing.T) {
	logger := discardLogger()

	t.Run("returns nil when nothing configured", func(t *testing.T) {
		t.Setenv(grafanaOAuthClientIDEnvVar, "")
		t.Setenv(grafanaOAuthDeviceAuthURLEnvVar, "")
		t.Setenv(grafanaOAuthTokenURLEnvVar, "")
		t.Setenv(grafanaOAuthClientSecretEnvVar, "")
		assert.Nil(t, buildOAuthConfigFromEnv(logger))
	})

	t.Run("returns nil and warns when incomplete", func(t *testing.T) {
		t.Setenv(grafanaOAuthClientIDEnvVar, "id")
		t.Setenv(grafanaOAuthDeviceAuthURLEnvVar, "")
		t.Setenv(grafanaOAuthTokenURLEnvVar, "")
		t.Setenv(grafanaOAuthClientSecretEnvVar, "")
		assert.Nil(t, buildOAuthConfigFromEnv(logger))
	})

	t.Run("builds full config with defaults", func(t *testing.T) {
		t.Setenv(grafanaOAuthClientIDEnvVar, "grafana")
		t.Setenv(grafanaOAuthDeviceAuthURLEnvVar, "https://idp/device")
		t.Setenv(grafanaOAuthTokenURLEnvVar, "https://idp/token")
		t.Setenv(grafanaOAuthClientSecretEnvVar, "")
		t.Setenv(grafanaOAuthScopesEnvVar, "")
		t.Setenv(grafanaOAuthAudienceEnvVar, "grafana")

		cfg := buildOAuthConfigFromEnv(logger)
		require.NotNil(t, cfg)
		assert.True(t, cfg.Enabled())
		assert.Equal(t, "grafana", cfg.ClientID)
		assert.Empty(t, cfg.ClientSecret)
		assert.Equal(t, "https://idp/device", cfg.DeviceAuthURL)
		assert.Equal(t, defaultOAuthScopes, cfg.Scopes)
		assert.Equal(t, "grafana", cfg.Audience)
	})
}

func TestOAuthDeviceFlow(t *testing.T) {
	idp := newFakeIdP(t)
	cachePath := filepath.Join(t.TempDir(), "token.json")
	cfg := &OAuthConfig{
		ClientID:      "grafana",
		DeviceAuthURL: idp.deviceAuthURL(),
		TokenURL:      idp.tokenURL(),
		Scopes:        []string{"openid"},
		CachePath:     cachePath,
		AuthTimeout:   30 * time.Second,
	}

	// First call starts the device flow and returns actionable instructions
	// containing the verification URL and user code.
	_, err := cfg.Token(true)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WXYZ-1234")
	assert.Contains(t, err.Error(), "/device/verify")

	// While the user hasn't approved yet, repeated calls keep returning
	// instructions and do NOT start a second device authorization.
	_, err = cfg.Token(true)
	require.Error(t, err)
	assert.Equal(t, 1, idp.deviceCallCount())

	// Simulate the user approving in their browser.
	idp.approve()

	// The background poller obtains and caches the token; a retry then succeeds.
	require.Eventually(t, func() bool {
		tok, err := cfg.Token(true)
		return err == nil && tok != nil && tok.AccessToken == "access-1"
	}, 10*time.Second, 100*time.Millisecond)

	assert.FileExists(t, cachePath)
}

func TestOAuthTokenNonInteractive(t *testing.T) {
	idp := newFakeIdP(t)

	t.Run("errors without starting a device flow when no token is cached", func(t *testing.T) {
		cfg := &OAuthConfig{
			ClientID:      "grafana",
			DeviceAuthURL: idp.deviceAuthURL(),
			TokenURL:      idp.tokenURL(),
			CachePath:     filepath.Join(t.TempDir(), "token.json"),
		}
		_, err := cfg.Token(false)
		require.Error(t, err)
		assert.Equal(t, 0, idp.deviceCallCount(), "no device authorization should be started")
		assert.Nil(t, cfg.pending)
	})

	t.Run("returns a valid cached token without any network call", func(t *testing.T) {
		cachePath := filepath.Join(t.TempDir(), "token.json")
		writeTokenFile(t, cachePath, &oauth2.Token{
			AccessToken: "cached", TokenType: "Bearer", Expiry: time.Now().Add(time.Hour),
		})
		cfg := &OAuthConfig{
			ClientID:      "grafana",
			DeviceAuthURL: idp.deviceAuthURL(),
			TokenURL:      idp.tokenURL(),
			CachePath:     cachePath,
		}
		tok, err := cfg.Token(false)
		require.NoError(t, err)
		assert.Equal(t, "cached", tok.AccessToken)
	})
}

func TestOAuthLoadsAndRefreshesCachedToken(t *testing.T) {
	idp := newFakeIdP(t)
	cachePath := filepath.Join(t.TempDir(), "token.json")
	// Seed an expired access token that still has a refresh token.
	writeTokenFile(t, cachePath, &oauth2.Token{
		AccessToken:  "old",
		TokenType:    "Bearer",
		RefreshToken: "refresh-1",
		Expiry:       time.Now().Add(-time.Hour),
	})

	cfg := &OAuthConfig{
		ClientID:      "grafana",
		DeviceAuthURL: idp.deviceAuthURL(),
		TokenURL:      idp.tokenURL(),
		CachePath:     cachePath,
	}

	tok, err := cfg.Token(true)
	require.NoError(t, err)
	assert.Equal(t, "access-refreshed", tok.AccessToken)
	assert.Equal(t, 0, idp.deviceCallCount(), "refresh must not trigger a device login")

	reloaded := cfg.load()
	require.NotNil(t, reloaded)
	assert.Equal(t, "refresh-2", reloaded.RefreshToken)
}

func TestOAuthConfigTokenNotConfigured(t *testing.T) {
	_, err := (&OAuthConfig{}).Token(true)
	require.Error(t, err)
}

func TestOAuthInteractiveAllowedContext(t *testing.T) {
	assert.True(t, oauthInteractiveAllowed(context.Background()))
	assert.False(t, oauthInteractiveAllowed(WithoutInteractiveOAuth(context.Background())))
}

func TestAuthRoundTripperOAuth(t *testing.T) {
	newMock := func(captured **http.Request) *capturingMockRT {
		return &capturingMockRT{fn: func(req *http.Request) (*http.Response, error) {
			*captured = req
			return &http.Response{StatusCode: 200}, nil
		}}
	}

	// Pre-seed a valid cached token so RoundTrip needs no device login/network.
	seedValid := func(t *testing.T) *OAuthConfig {
		cachePath := filepath.Join(t.TempDir(), "token.json")
		writeTokenFile(t, cachePath, &oauth2.Token{
			AccessToken: "bearer-tok",
			TokenType:   "Bearer",
			Expiry:      time.Now().Add(time.Hour),
		})
		return &OAuthConfig{
			ClientID:      "id",
			DeviceAuthURL: "https://idp/device",
			TokenURL:      "https://idp/token",
			CachePath:     cachePath,
		}
	}

	t.Run("sets bearer token from oauth", func(t *testing.T) {
		var captured *http.Request
		rt := NewAuthRoundTripper(newMock(&captured), "", "", "", nil)
		rt.oauth = seedValid(t)

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, "Bearer bearer-tok", captured.Header.Get("Authorization"))
	})

	t.Run("oauth takes precedence over static api key", func(t *testing.T) {
		var captured *http.Request
		rt := NewAuthRoundTripper(newMock(&captured), "", "", "static-key", nil)
		rt.oauth = seedValid(t)

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, "Bearer bearer-tok", captured.Header.Get("Authorization"))
	})

	t.Run("obo tokens take precedence over oauth", func(t *testing.T) {
		var captured *http.Request
		// An OAuth config whose Token() would fail if ever called (no server).
		rt := NewAuthRoundTripper(newMock(&captured), "access-tok", "id-tok", "", nil)
		rt.oauth = &OAuthConfig{ClientID: "id", DeviceAuthURL: "https://idp/device", TokenURL: "https://idp/token"}

		req, _ := http.NewRequest("GET", "http://example.com", nil)
		_, err := rt.RoundTrip(req)
		require.NoError(t, err)
		assert.Equal(t, "access-tok", captured.Header.Get("X-Access-Token"))
		assert.Equal(t, "id-tok", captured.Header.Get("X-Grafana-Id"))
		assert.Empty(t, captured.Header.Get("Authorization"))
	})
}
