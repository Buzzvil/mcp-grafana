package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"

	aapi "github.com/grafana/amixr-api-go-client"
	mcpgrafana "github.com/grafana/mcp-grafana"
	"github.com/stretchr/testify/require"
)

func TestOncallClientUsesCheckedTransport(t *testing.T) {
	const apiKey = "synthetic-oncall-key"
	type receivedRequest struct {
		path          string
		authorization string
		grafanaURL    string
		extraHeader   string
	}
	received := make(chan receivedRequest, 1)
	oncall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- receivedRequest{
			path:          r.URL.Path,
			authorization: r.Header.Get("Authorization"),
			grafanaURL:    r.Header.Get("X-Grafana-URL"),
			extraHeader:   r.Header.Get("X-Private"),
		}
		_ = json.NewEncoder(w).Encode(aapi.PaginatedUsersResponse{
			Users: []*aapi.User{{ID: "u1"}},
		})
	}))
	defer oncall.Close()

	cfg := mcpgrafana.GrafanaConfig{
		URL:          "https://grafana.example",
		APIKey:       apiKey,
		ExtraHeaders: map[string]string{"X-Private": "synthetic-extra-secret"},
	}
	ctx := mcpgrafana.WithGrafanaConfig(context.Background(), cfg)
	client, err := newOncallClient(cfg, oncall.URL+"/oncall")
	require.NoError(t, err)
	var result aapi.PaginatedUsersResponse
	require.NoError(t, client.get(ctx, "users", "", nil, &result))
	require.Len(t, result.Users, 1)
	require.Equal(t, "u1", result.Users[0].ID)
	got := <-received
	require.Equal(t, "/oncall/api/v1/users/", got.path)
	require.Equal(t, apiKey, got.authorization)
	require.Equal(t, cfg.URL, got.grafanaURL)
	require.Empty(t, got.extraHeader)
}

func TestOncallClientRejectsRedirectsWithCredentials(t *testing.T) {
	var externalRequests atomic.Int32
	external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		externalRequests.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer external.Close()

	var outsidePathRequests atomic.Int32
	oncall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/outside" {
			outsidePathRequests.Add(1)
			w.WriteHeader(http.StatusOK)
			return
		}
		if r.URL.Query().Get("outside") == "true" {
			http.Redirect(w, r, "/outside", http.StatusFound)
			return
		}
		http.Redirect(w, r, external.URL+"/capture", http.StatusFound)
	}))
	defer oncall.Close()

	cfg := mcpgrafana.GrafanaConfig{URL: "https://grafana.example", APIKey: "synthetic-oncall-key"}
	client, err := newOncallClient(cfg, oncall.URL+"/oncall")
	require.NoError(t, err)
	var result aapi.PaginatedUsersResponse
	require.Error(t, client.get(context.Background(), "users", "", nil, &result))
	require.EqualValues(t, 0, externalRequests.Load())

	require.Error(t, client.get(context.Background(), "users", "", map[string][]string{"outside": {"true"}}, &result))
	require.EqualValues(t, 0, outsidePathRequests.Load())
}

func TestOncallAlertGroupRequestPreservesFilters(t *testing.T) {
	received := make(chan url.Values, 1)
	oncall := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.URL.Query()
		_ = json.NewEncoder(w).Encode(aapi.PaginatedAlertGroupsResponse{
			AlertGroups: []*aapi.AlertGroup{{ID: "synthetic-group"}},
		})
	}))
	defer oncall.Close()

	grafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonData": map[string]string{"onCallApiUrl": oncall.URL + "/oncall"},
		})
	}))
	defer grafana.Close()

	ctx := mcpgrafana.WithGrafanaConfig(context.Background(), mcpgrafana.GrafanaConfig{
		URL: grafana.URL, APIKey: "synthetic-oncall-key",
	})
	groups, err := amixrListAlertGroups(ctx, ListAlertGroupsParams{
		Page: 2, AlertGroupID: "group", TeamID: "team", Labels: []string{"env:dev", "severity:high"},
	})
	require.NoError(t, err)
	require.Len(t, groups, 1)
	require.Equal(t, "synthetic-group", groups[0].ID)
	query := <-received
	require.Equal(t, "2", query.Get("page"))
	require.Equal(t, "group", query.Get("id"))
	require.Equal(t, "team", query.Get("team_id"))
	require.Equal(t, []string{"env:dev", "severity:high"}, query["label"])
}
