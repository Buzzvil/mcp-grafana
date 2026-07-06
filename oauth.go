package mcpgrafana

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
)

const (
	// grafanaOAuthClientIDEnvVar is the OAuth2 client ID used for the
	// client-credentials grant when authenticating to Grafana via OAuth.
	grafanaOAuthClientIDEnvVar = "GRAFANA_OAUTH_CLIENT_ID"
	// grafanaOAuthClientSecretEnvVar is the OAuth2 client secret.
	grafanaOAuthClientSecretEnvVar = "GRAFANA_OAUTH_CLIENT_SECRET"
	// grafanaOAuthTokenURLEnvVar is the OAuth2 token endpoint that issues
	// access tokens for the client-credentials grant.
	grafanaOAuthTokenURLEnvVar = "GRAFANA_OAUTH_TOKEN_URL"
	// grafanaOAuthScopesEnvVar is a comma- or space-separated list of scopes
	// to request. Optional.
	grafanaOAuthScopesEnvVar = "GRAFANA_OAUTH_SCOPES"
	// grafanaOAuthAudienceEnvVar is an optional audience parameter sent to the
	// token endpoint. Required by some providers (e.g. Auth0).
	grafanaOAuthAudienceEnvVar = "GRAFANA_OAUTH_AUDIENCE"
)

// OAuthConfig holds the OAuth2 client-credentials settings used to authenticate
// to Grafana. When configured, the MCP server exchanges the client ID/secret
// for a short-lived bearer token at the token endpoint and sends it as
// `Authorization: Bearer <token>` on every Grafana API request, in place of a
// static service account token. Tokens are cached and refreshed automatically
// by the underlying oauth2 token source.
//
// An *OAuthConfig is shared by pointer across the copies of GrafanaConfig that
// flow through the request context, so the cached token source is reused for
// the lifetime of the process rather than re-created per request.
type OAuthConfig struct {
	// ClientID is the OAuth2 client identifier.
	ClientID string
	// ClientSecret is the OAuth2 client secret.
	ClientSecret string
	// TokenURL is the OAuth2 token endpoint that issues access tokens.
	TokenURL string
	// Scopes are the OAuth2 scopes to request. May be empty.
	Scopes []string
	// EndpointParams carries additional parameters sent to the token endpoint,
	// such as an "audience" value required by some providers (e.g. Auth0).
	EndpointParams url.Values

	// HTTPClient is an optional HTTP client used to reach the token endpoint.
	// When nil, the oauth2 default client is used. It is intentionally
	// independent of the Grafana TLS configuration, since the OAuth provider is
	// usually a separate host with its own trust chain.
	HTTPClient *http.Client

	once        sync.Once
	tokenSource oauth2.TokenSource
}

// Enabled reports whether the config carries the minimum fields required to
// perform a client-credentials token exchange. A nil receiver is not enabled,
// which lets callers write cfg.OAuth.Enabled() without a nil check.
func (c *OAuthConfig) Enabled() bool {
	return c != nil && c.ClientID != "" && c.ClientSecret != "" && c.TokenURL != ""
}

// tokenSourceOrNil returns a cached, auto-refreshing token source built from the
// client-credentials config. It is initialised once and reused so that tokens
// are not re-fetched on every request. Returns nil if the config is not enabled.
func (c *OAuthConfig) tokenSourceOrNil() oauth2.TokenSource {
	if !c.Enabled() {
		return nil
	}
	c.once.Do(func() {
		// Use a background context (not a request context) so that token
		// refreshes are not cancelled when the request that triggered them
		// completes. The token source caches this context internally.
		ctx := context.Background()
		if c.HTTPClient != nil {
			ctx = context.WithValue(ctx, oauth2.HTTPClient, c.HTTPClient)
		}
		cc := &clientcredentials.Config{
			ClientID:       c.ClientID,
			ClientSecret:   c.ClientSecret,
			TokenURL:       c.TokenURL,
			Scopes:         c.Scopes,
			EndpointParams: c.EndpointParams,
			AuthStyle:      oauth2.AuthStyleAutoDetect,
		}
		c.tokenSource = cc.TokenSource(ctx)
	})
	return c.tokenSource
}

// Token fetches an OAuth2 access token, returning a cached token when one is
// still valid and transparently refreshing it otherwise. It is safe for
// concurrent use. It returns an error if the config is not enabled or the token
// exchange fails.
func (c *OAuthConfig) Token() (*oauth2.Token, error) {
	ts := c.tokenSourceOrNil()
	if ts == nil {
		return nil, fmt.Errorf("grafana OAuth is not configured")
	}
	return ts.Token()
}

// oauthConfigFromEnv builds an OAuthConfig from the GRAFANA_OAUTH_* environment
// variables, returning nil when OAuth is not configured. The result is cached:
// the environment is read once for the lifetime of the process (it does not
// change), which keeps the token source stable across the per-request header
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
// settings are incomplete (in which case it logs a warning), so a nil result
// always means "OAuth disabled".
func buildOAuthConfigFromEnv(logger *slog.Logger) *OAuthConfig {
	clientID := strings.TrimSpace(os.Getenv(grafanaOAuthClientIDEnvVar))
	clientSecret := os.Getenv(grafanaOAuthClientSecretEnvVar)
	tokenURL := strings.TrimSpace(os.Getenv(grafanaOAuthTokenURLEnvVar))

	// Nothing configured: OAuth is simply disabled.
	if clientID == "" && clientSecret == "" && tokenURL == "" {
		return nil
	}

	cfg := &OAuthConfig{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		TokenURL:     tokenURL,
		Scopes:       parseOAuthScopes(os.Getenv(grafanaOAuthScopesEnvVar)),
	}
	if audience := strings.TrimSpace(os.Getenv(grafanaOAuthAudienceEnvVar)); audience != "" {
		cfg.EndpointParams = url.Values{"audience": {audience}}
	}

	if !cfg.Enabled() {
		logger.Warn("Incomplete Grafana OAuth configuration, ignoring it. All of "+
			grafanaOAuthClientIDEnvVar+", "+grafanaOAuthClientSecretEnvVar+" and "+
			grafanaOAuthTokenURLEnvVar+" are required to enable OAuth.",
			"client_id_set", clientID != "",
			"client_secret_set", clientSecret != "",
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
