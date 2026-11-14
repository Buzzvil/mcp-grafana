package tools

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/grafana/mcp-grafana"
	"github.com/hashicorp/go-retryablehttp"
)

// oncallClient uses the same destination-checked transport as Grafana API
// requests. The upstream amixr client keeps its retryable HTTP client private,
// so its transport cannot be protected against redirects by callers.
type oncallClient struct {
	baseURL    string
	grafanaURL string
	apiKey     string
	httpClient *retryablehttp.Client
	config     mcpgrafana.GrafanaConfig
}

func newOncallClient(cfg mcpgrafana.GrafanaConfig, oncallURL string) (*oncallClient, error) {
	oncallURL = strings.TrimRight(oncallURL, "/")
	if err := mcpgrafana.ValidateGrafanaURL(oncallURL); err != nil {
		return nil, fmt.Errorf("invalid OnCall API URL: %w", err)
	}
	parsed, err := url.Parse(oncallURL)
	if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("invalid OnCall API URL: query and fragment are not allowed")
	}

	// The OnCall library sends the API key explicitly. Do not forward any
	// Grafana-only credentials or extra headers to this separate endpoint.
	oncallCfg := cfg
	oncallCfg.URL = oncallURL
	oncallCfg.APIKey = ""
	oncallCfg.BasicAuth = nil
	oncallCfg.AccessToken = ""
	oncallCfg.IDToken = ""
	oncallCfg.ExtraHeaders = nil
	oncallCfg.OrgID = 0
	transport, err := mcpgrafana.BuildTransport(&oncallCfg, nil,
		mcpgrafana.WithoutAuth(), mcpgrafana.WithoutOrgID())
	if err != nil {
		return nil, fmt.Errorf("building OnCall transport: %w", err)
	}
	baseURL := oncallURL + "/api/v1/"
	if strings.HasSuffix(parsed.Path, "/api/v1") {
		baseURL = oncallURL + "/"
	}
	retryClient := retryablehttp.NewClient()
	retryClient.Logger = nil
	retryClient.HTTPClient = &http.Client{Transport: transport, Timeout: cfg.Timeout}
	return &oncallClient{
		baseURL:    baseURL,
		grafanaURL: cfg.URL,
		apiKey:     cfg.APIKey,
		httpClient: retryClient,
		config:     oncallCfg,
	}, nil
}

func (c *oncallClient) get(ctx context.Context, resource, id string, query url.Values, out any) error {
	if id == "." || id == ".." || strings.ContainsAny(id, "/\\") {
		return errors.New("invalid OnCall resource ID")
	}
	requestURL := c.baseURL + resource
	if id != "" {
		requestURL += "/" + url.PathEscape(id)
	}
	requestURL += "/"
	if len(query) > 0 {
		requestURL += "?" + query.Encode()
	}
	// ExtraHeadersRoundTripper also reads config from the request context.
	// Replace it with the stripped OnCall config before sending this request.
	req, err := retryablehttp.NewRequestWithContext(mcpgrafana.WithGrafanaConfig(ctx, c.config), http.MethodGet, requestURL, nil)
	if err != nil {
		return fmt.Errorf("creating OnCall request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", c.apiKey)
	req.Header.Set("X-Grafana-URL", c.grafanaURL)
	req.Header.Set("User-Agent", "amixr-api-go-client")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("sending OnCall request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("oncall API returned HTTP %d", resp.StatusCode)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("decoding OnCall response: %w", err)
	}
	return nil
}

func oncallListQuery(page int) url.Values {
	query := make(url.Values)
	if page > 0 {
		query.Set("page", strconv.Itoa(page))
	}
	return query
}
