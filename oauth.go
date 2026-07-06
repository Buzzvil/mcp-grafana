package mcpgrafana

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/oauth2"
)

const (
	// grafanaOAuthClientIDEnvVar is the OAuth2 client ID of the public client
	// used for the Device Authorization Grant login.
	grafanaOAuthClientIDEnvVar = "GRAFANA_OAUTH_CLIENT_ID"
	// grafanaOAuthClientSecretEnvVar is an optional client secret. Leave it unset
	// for a public client (the recommended, secret-less setup).
	grafanaOAuthClientSecretEnvVar = "GRAFANA_OAUTH_CLIENT_SECRET"
	// grafanaOAuthDeviceAuthURLEnvVar is the OAuth2 device authorization endpoint
	// (RFC 8628), e.g. https://idp/application/o/device/.
	grafanaOAuthDeviceAuthURLEnvVar = "GRAFANA_OAUTH_DEVICE_AUTH_URL"
	// grafanaOAuthTokenURLEnvVar is the OAuth2 token endpoint.
	grafanaOAuthTokenURLEnvVar = "GRAFANA_OAUTH_TOKEN_URL"
	// grafanaOAuthScopesEnvVar is a comma- or space-separated list of scopes.
	grafanaOAuthScopesEnvVar = "GRAFANA_OAUTH_SCOPES"
	// grafanaOAuthAudienceEnvVar is an optional audience parameter for the token.
	grafanaOAuthAudienceEnvVar = "GRAFANA_OAUTH_AUDIENCE"
	// grafanaOAuthTokenCacheEnvVar overrides the on-disk token cache path.
	grafanaOAuthTokenCacheEnvVar = "GRAFANA_OAUTH_TOKEN_CACHE"
	// grafanaOAuthAuthTimeoutEnvVar bounds how long to wait for device approval
	// (Go duration).
	grafanaOAuthAuthTimeoutEnvVar = "GRAFANA_OAUTH_AUTH_TIMEOUT"

	defaultOAuthAuthTimeout = 10 * time.Minute
	oauthRefreshTimeout     = 30 * time.Second
)

// defaultOAuthScopes requests an ID token plus a refresh token (offline_access)
// so that expired access tokens can be refreshed silently without another
// device login. Override with GRAFANA_OAUTH_SCOPES.
var defaultOAuthScopes = []string{"openid", "profile", "email", "offline_access"}

// OAuthConfig holds the OAuth2 Device Authorization Grant (RFC 8628) settings
// used to authenticate to Grafana as the interactive user, in place of a
// long-lived service account token.
//
// Because the device flow has no redirect/callback, it works even when the MCP
// server runs somewhere without a browser (a container, a remote host, over
// SSH): on the first Grafana request the server surfaces a verification URL and
// a short user code, the user approves it in any browser, and the server polls
// the token endpoint in the background. Only short-lived, per-user, revocable
// tokens ever live on the machine running the server — no static shared secret.
//
// The access token and (when issued) refresh token are cached on disk so tokens
// survive restarts; expired access tokens are refreshed automatically. An
// *OAuthConfig is shared by pointer across the copies of GrafanaConfig that flow
// through the request context, so the cached token is reused process-wide.
type OAuthConfig struct {
	// ClientID is the public OAuth2 client identifier.
	ClientID string
	// ClientSecret is optional; leave empty for a public client.
	ClientSecret string
	// DeviceAuthURL is the OAuth2 device authorization endpoint (RFC 8628).
	DeviceAuthURL string
	// TokenURL is the OAuth2 token endpoint.
	TokenURL string
	// Scopes are the OAuth2 scopes to request.
	Scopes []string
	// Audience, when set, is sent as the `audience` parameter to the device
	// authorization endpoint (required by some providers, e.g. Auth0).
	Audience string
	// CachePath is the file the token is persisted to. When empty a per-config
	// path under the user config dir is used.
	CachePath string
	// AuthTimeout bounds how long a device login may stay pending.
	AuthTimeout time.Duration

	logger *slog.Logger

	mu      sync.Mutex
	cur     *oauth2.Token
	loaded  bool
	pending *deviceFlow
}

// deviceFlow tracks an in-progress device authorization. It is created when a
// tool request first needs a token and cleared once the login completes (so a
// subsequent failure can start a fresh flow).
type deviceFlow struct {
	userCode                string
	verificationURI         string
	verificationURIComplete string
	done                    bool
	err                     error
}

// Enabled reports whether the config carries the fields required to perform the
// device login. A nil receiver is not enabled, which lets callers write
// cfg.OAuth.Enabled() without a nil check.
func (c *OAuthConfig) Enabled() bool {
	return c != nil && c.ClientID != "" && c.DeviceAuthURL != "" && c.TokenURL != ""
}

// noInteractiveOAuthKey marks a context in which the OAuth flow must not start
// an interactive device login (e.g. server-startup work such as proxied-tool
// discovery or the public-URL fetch). Such contexts still use a cached or
// refreshable token, but never begin a login that needs a human.
type noInteractiveOAuthKey struct{}

// WithoutInteractiveOAuth returns a context in which OAuthConfig.Token will not
// start an interactive device login. Use it for background/startup work so the
// login happens lazily on the first real tool request instead.
func WithoutInteractiveOAuth(ctx context.Context) context.Context {
	return context.WithValue(ctx, noInteractiveOAuthKey{}, true)
}

// oauthInteractiveAllowed reports whether interactive login is permitted for the
// context. It defaults to true; WithoutInteractiveOAuth opts out.
func oauthInteractiveAllowed(ctx context.Context) bool {
	disabled, _ := ctx.Value(noInteractiveOAuthKey{}).(bool)
	return !disabled
}

// Token returns a valid OAuth2 access token, refreshing a cached token when
// possible. When allowInteractive is true and no valid or refreshable token
// exists, it starts (or continues) a device login and returns an actionable
// error telling the user which URL to open and which code to enter; the token
// is fetched in the background, so a retry after approval succeeds. When
// allowInteractive is false it returns an error instead of starting a login. It
// is safe for concurrent use.
func (c *OAuthConfig) Token(allowInteractive bool) (*oauth2.Token, error) {
	if !c.Enabled() {
		return nil, fmt.Errorf("grafana OAuth is not configured")
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.loaded {
		c.cur = c.load()
		c.loaded = true
	}

	// Reuse a still-valid access token.
	if c.cur.Valid() {
		return c.cur, nil
	}

	// Try to refresh using a stored refresh token before falling back to login.
	if c.cur != nil && c.cur.RefreshToken != "" {
		if tok, err := c.refresh(c.cur); err == nil {
			c.storeLocked(tok)
			return tok, nil
		} else if !allowInteractive {
			return nil, fmt.Errorf("failed to refresh Grafana OAuth token: %w", err)
		} else {
			c.log().Warn("Grafana OAuth token refresh failed, starting a new device login", "error", err)
		}
	}

	if !allowInteractive {
		return nil, fmt.Errorf("no valid Grafana OAuth token is cached; a device login is required and will start on the first Grafana tool request")
	}

	// A device login is already in progress.
	if p := c.pending; p != nil {
		if !p.done {
			return nil, p.instructionsErr()
		}
		// The background poller finished. On success c.cur was populated;
		// clear the pending flow either way so a failure can be retried.
		perr := p.err
		c.pending = nil
		if c.cur.Valid() {
			return c.cur, nil
		}
		if perr != nil {
			return nil, perr
		}
	}

	// Start a new device login and return instructions.
	p, err := c.startDeviceFlow()
	if err != nil {
		return nil, err
	}
	c.pending = p
	return nil, p.instructionsErr()
}

func (c *OAuthConfig) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint: oauth2.Endpoint{
			DeviceAuthURL: c.DeviceAuthURL,
			TokenURL:      c.TokenURL,
			AuthStyle:     oauth2.AuthStyleAutoDetect,
		},
		Scopes: c.Scopes,
	}
}

func (c *OAuthConfig) authTimeout() time.Duration {
	if c.AuthTimeout > 0 {
		return c.AuthTimeout
	}
	return defaultOAuthAuthTimeout
}

func (c *OAuthConfig) log() *slog.Logger {
	if c.logger != nil {
		return c.logger
	}
	return slog.New(slog.DiscardHandler)
}

func (c *OAuthConfig) audienceOptions() []oauth2.AuthCodeOption {
	if c.Audience == "" {
		return nil
	}
	return []oauth2.AuthCodeOption{oauth2.SetAuthURLParam("audience", c.Audience)}
}

// refresh exchanges a stored refresh token for a fresh access token.
func (c *OAuthConfig) refresh(old *oauth2.Token) (*oauth2.Token, error) {
	ctx, cancel := context.WithTimeout(context.Background(), oauthRefreshTimeout)
	defer cancel()
	return c.oauth2Config().TokenSource(ctx, old).Token()
}

// startDeviceFlow initiates a device authorization request and kicks off a
// background goroutine that polls the token endpoint until the user approves.
// It must be called with c.mu held. It returns quickly with the verification
// details; it never blocks on the human.
func (c *OAuthConfig) startDeviceFlow() (*deviceFlow, error) {
	conf := c.oauth2Config()
	ctx, cancel := context.WithTimeout(context.Background(), c.authTimeout())

	da, err := conf.DeviceAuth(ctx, c.audienceOptions()...)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to start Grafana OAuth device authorization: %w", err)
	}

	p := &deviceFlow{
		userCode:                da.UserCode,
		verificationURI:         da.VerificationURI,
		verificationURIComplete: da.VerificationURIComplete,
	}

	c.log().Info("Grafana OAuth device login required",
		"verification_uri", da.VerificationURI, "user_code", da.UserCode)

	go func() {
		defer cancel()
		tok, err := conf.DeviceAccessToken(ctx, da)

		c.mu.Lock()
		defer c.mu.Unlock()
		if err != nil {
			p.err = fmt.Errorf("device login did not complete: %w", err)
		} else {
			c.storeLocked(tok)
			c.log().Info("Grafana OAuth device login completed")
		}
		p.done = true
	}()

	return p, nil
}

// instructionsErr returns the actionable error shown to the user for a pending
// device login.
func (p *deviceFlow) instructionsErr() error {
	if p.verificationURIComplete != "" {
		return fmt.Errorf("sign in to Grafana — open %s in a browser to approve "+
			"(user code %s), then retry your request", p.verificationURIComplete, p.userCode)
	}
	return fmt.Errorf("sign in to Grafana — open %s in a browser and enter code %s, "+
		"then retry your request", p.verificationURI, p.userCode)
}

// storeLocked updates the in-memory token and persists it to disk (best effort).
// It must be called with c.mu held.
func (c *OAuthConfig) storeLocked(tok *oauth2.Token) {
	c.cur = tok
	if err := c.save(tok); err != nil {
		c.log().Warn("Failed to persist Grafana OAuth token cache", "error", err)
	}
}

func (c *OAuthConfig) cachePath() string {
	if c.CachePath != "" {
		return c.CachePath
	}
	dir, err := os.UserConfigDir()
	if err != nil || dir == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(c.ClientID + "|" + c.DeviceAuthURL + "|" + c.TokenURL))
	name := "token-" + hex.EncodeToString(sum[:6]) + ".json"
	return filepath.Join(dir, "mcp-grafana", name)
}

func (c *OAuthConfig) save(tok *oauth2.Token) error {
	path := c.cachePath()
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(tok)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func (c *OAuthConfig) load() *oauth2.Token {
	path := c.cachePath()
	if path == "" {
		return nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var tok oauth2.Token
	if err := json.Unmarshal(data, &tok); err != nil {
		return nil
	}
	if tok.AccessToken == "" && tok.RefreshToken == "" {
		return nil
	}
	return &tok
}

// oauthConfigFromEnv builds an OAuthConfig from the GRAFANA_OAUTH_* environment
// variables, returning nil when OAuth is not configured. The result is cached:
// the environment is read once for the lifetime of the process (it does not
// change), which keeps the cached token stable across the per-request header
// context funcs used by the HTTP and SSE transports.
func oauthConfigFromEnv(logger *slog.Logger) *OAuthConfig {
	envOAuthOnce.Do(func() {
		envOAuthConfig = buildOAuthConfigFromEnv(logger)
	})
	return envOAuthConfig
}

var (
	envOAuthOnce   sync.Once
	envOAuthConfig *OAuthConfig
)

// buildOAuthConfigFromEnv reads the GRAFANA_OAUTH_* environment variables into
// an OAuthConfig. It returns nil when no OAuth settings are present, or when the
// settings are incomplete (logging a warning), so a nil result always means
// "OAuth disabled".
func buildOAuthConfigFromEnv(logger *slog.Logger) *OAuthConfig {
	clientID := strings.TrimSpace(os.Getenv(grafanaOAuthClientIDEnvVar))
	deviceAuthURL := strings.TrimSpace(os.Getenv(grafanaOAuthDeviceAuthURLEnvVar))
	tokenURL := strings.TrimSpace(os.Getenv(grafanaOAuthTokenURLEnvVar))
	clientSecret := os.Getenv(grafanaOAuthClientSecretEnvVar)

	// Nothing configured: OAuth is simply disabled.
	if clientID == "" && deviceAuthURL == "" && tokenURL == "" && clientSecret == "" {
		return nil
	}

	scopes := parseOAuthScopes(os.Getenv(grafanaOAuthScopesEnvVar))
	if scopes == nil {
		scopes = append([]string(nil), defaultOAuthScopes...)
	}

	cfg := &OAuthConfig{
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		DeviceAuthURL: deviceAuthURL,
		TokenURL:      tokenURL,
		Scopes:        scopes,
		Audience:      strings.TrimSpace(os.Getenv(grafanaOAuthAudienceEnvVar)),
		CachePath:     strings.TrimSpace(os.Getenv(grafanaOAuthTokenCacheEnvVar)),
		logger:        logger,
	}
	if raw := strings.TrimSpace(os.Getenv(grafanaOAuthAuthTimeoutEnvVar)); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil {
			cfg.AuthTimeout = d
		} else {
			logger.Warn("Invalid GRAFANA_OAUTH_AUTH_TIMEOUT, using default", "value", raw, "error", err)
		}
	}

	if !cfg.Enabled() {
		logger.Warn("Incomplete Grafana OAuth configuration, ignoring it. "+
			grafanaOAuthClientIDEnvVar+", "+grafanaOAuthDeviceAuthURLEnvVar+" and "+
			grafanaOAuthTokenURLEnvVar+" are all required to enable OAuth login.",
			"client_id_set", clientID != "",
			"device_auth_url_set", deviceAuthURL != "",
			"token_url_set", tokenURL != "")
		return nil
	}
	return cfg
}

// parseOAuthScopes splits a scope string on commas and whitespace, dropping
// empty entries. OAuth providers expect space-delimited scopes; commas are also
// accepted for consistency with other list-style env vars in this project.
func parseOAuthScopes(raw string) []string {
	fields := strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	if len(fields) == 0 {
		return nil
	}
	return fields
}
