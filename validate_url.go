package mcpgrafana

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
)

// ErrInvalidGrafanaURL is returned (wrapped) by ValidateGrafanaURL when the
// input is not an absolute HTTP or HTTPS URL with a non-empty host. Detect
// with errors.Is.
//
// The nav.go guard in tools/navigation.go:generateDeeplink wraps this
// sentinel when config.URL is malformed (e.g. coming from a bad
// /api/frontend/settings appUrl response), distinguishing that case from
// missing-URL cases for callers that discriminate via errors.Is.
var ErrInvalidGrafanaURL = errors.New("invalid Grafana URL")

// sameGrafanaBaseURL compares the complete configured endpoint, including its
// base path. A token configured for one Grafana must not follow a request URL
// to another endpoint on the same host.
func sameGrafanaBaseURL(a, b string) bool {
	ua, errA := url.Parse(strings.TrimRight(a, "/"))
	ub, errB := url.Parse(strings.TrimRight(b, "/"))
	return errA == nil && errB == nil && ua.Host != "" && ub.Host != "" &&
		sameGrafanaOrigin(ua, ub) && path.Clean(ua.Path) == path.Clean(ub.Path) &&
		ua.RawQuery == "" && ub.RawQuery == "" && ua.Fragment == "" && ub.Fragment == ""
}

func sameGrafanaOrigin(a, b *url.URL) bool {
	port := func(u *url.URL) string {
		if u.Port() != "" {
			return u.Port()
		}
		if u.Scheme == "https" {
			return "443"
		}
		return "80"
	}
	return a.User == nil && b.User == nil && a.Scheme == b.Scheme &&
		strings.EqualFold(a.Hostname(), b.Hostname()) && port(a) == port(b)
}

// AllowGrafanaURLMiddleware limits request-selected Grafana endpoints to the
// server's configured URL and the exact URLs in GRAFANA_ALLOWED_URLS. This is
// the outbound destination policy for the HTTP/SSE entrypoints.
func AllowGrafanaURLMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get(grafanaURLHeader)
		if raw != "" {
			configured := strings.TrimRight(os.Getenv(grafanaURLEnvVar), "/")
			if configured == "" {
				configured = defaultGrafanaURL
			}
			configuredTarget := sameGrafanaBaseURL(raw, configured)
			allowed := configuredTarget
			for _, candidate := range strings.Split(os.Getenv("GRAFANA_ALLOWED_URLS"), ",") {
				if sameGrafanaBaseURL(raw, strings.TrimSpace(candidate)) {
					allowed = true
					break
				}
			}
			if !allowed {
				http.Error(w, "X-Grafana-URL is not an allowed Grafana endpoint", http.StatusBadRequest)
				return
			}
			_, _, basicAuth := r.BasicAuth()
			if !configuredTarget && r.Header.Get(grafanaServiceAccountTokenHeader) == "" &&
				r.Header.Get(grafanaAPIKeyHeader) == "" && !basicAuth {
				http.Error(w, "X-Grafana-URL needs request credentials for this endpoint", http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

// ValidateGrafanaURL returns nil if u is an absolute HTTP or HTTPS URL with a
// non-empty host. Trailing slashes are trimmed before validation so callers do
// not need to pre-normalize; this is the single canonicalization point shared
// by ValidateGrafanaURLMiddleware and the nav.go guard. On failure the
// returned error wraps ErrInvalidGrafanaURL.
//
// url.Parse alone is too lenient: it accepts relative references (/foo),
// unusual schemes (javascript:alert(1)), and URLs without a host (http://).
// ParseRequestURI plus a scheme allow-list plus a host check is the standard
// pattern for validating request-supplied URL headers.
func ValidateGrafanaURL(u string) error {
	u = strings.TrimRight(u, "/")
	if u == "" {
		return fmt.Errorf("%w: URL is empty", ErrInvalidGrafanaURL)
	}
	pu, err := url.ParseRequestURI(u)
	if err != nil {
		return fmt.Errorf("%w: %v (set a valid http:// or https:// URL)", ErrInvalidGrafanaURL, err)
	}
	if pu.Scheme != "http" && pu.Scheme != "https" {
		return fmt.Errorf("%w: scheme %q not allowed (must be http or https)", ErrInvalidGrafanaURL, pu.Scheme)
	}
	if pu.Host == "" {
		return fmt.Errorf("%w: URL has no host", ErrInvalidGrafanaURL)
	}
	// Reject embedded userinfo (http://user:pass@host). Those values get logged
	// raw in the extractors' slog.Debug lines, which is a credential-in-log
	// leak risk. Tracked in issue #776.
	if pu.User != nil {
		return fmt.Errorf("%w: embedded credentials not allowed", ErrInvalidGrafanaURL)
	}
	return nil
}

// ValidateGrafanaURLMiddleware returns an http.Handler middleware that rejects
// requests whose X-Grafana-URL header is present but fails ValidateGrafanaURL,
// responding with 400 Bad Request. Requests without the header pass through
// unchanged (downstream extractors apply the env-variable fallback).
//
// Library consumers that wire mcp-grafana's context functions into their own
// http.Server should install this middleware to match the binary's defensive
// behavior. Consumers that call NewGrafanaClient directly (stdio or
// programmatic construction) should pre-validate the URL with
// ValidateGrafanaURL instead.
func ValidateGrafanaURLMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if raw := r.Header.Get(grafanaURLHeader); raw != "" {
			if err := ValidateGrafanaURL(raw); err != nil {
				http.Error(w, fmt.Sprintf("invalid X-Grafana-URL header: %v", err), http.StatusBadRequest)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
