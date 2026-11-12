package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/meitner-se/go-lti"
)

// assetProcessorServer is a platform's Asset Processor services: its access tokens and their
// scopes, the assets it keeps, its processors and its deployments. It records what the hooks got.
type assetProcessorServer struct {
	tokens      map[string][]lti.Scope
	assets      map[string]AssetDownload
	processors  map[string]bool
	deployments map[string]bool

	reports     []lti.Report
	acceptances []lti.EulaAcceptance
	cleared     []string
	required    []bool
	closed      int
}

const (
	assetURL         = "https://platform.example.com/lti/assets/asset-1"
	assetReportURL   = "https://platform.example.com/lti/asset-reports/processor-1"
	eulaServiceURL   = "https://platform.example.com/lti/eula/deployment-1"
	validReport      = `{"assetId": "asset-1", "type": "originality", "timestamp": "2026-11-10T12:00:00.123456Z", "priority": 2, "processingProgress": "Processed", "result": "12%"}`
	validAcceptance  = `{"userId": "user-1", "accepted": true, "timestamp": "2026-11-10T12:00:00.123456Z"}`
	validEulaSetting = `{"eulaRequired": false}`
)

// trackedBody is an asset's bytes that count their closing.
type trackedBody struct {
	io.Reader

	closed *int
}

func (b trackedBody) Close() error {
	*b.closed++

	return nil
}

func newAssetProcessorServer() *assetProcessorServer {
	return &assetProcessorServer{
		tokens: map[string][]lti.Scope{
			"token-all":    {lti.ScopeAssetReadOnly, lti.ScopeReport, lti.ScopeEulaUser, lti.ScopeEulaDeployment},
			"token-scores": {lti.ScopeAGSScore},
		},
		assets: map[string]AssetDownload{
			"asset-1":        {Body: nil, ContentType: "application/pdf", Size: 0, RedirectURL: ""},
			"asset-redirect": {Body: nil, ContentType: "", Size: 0, RedirectURL: "https://storage.example.com/asset-1?signature=abc"},
		},
		processors:  map[string]bool{"processor-1": true},
		deployments: map[string]bool{"deployment-1": true},
	}
}

func (s *assetProcessorServer) authorize(_ *http.Request, token string, _ lti.Scope) (ServiceClient, error) {
	granted, ok := s.tokens[token]
	if !ok {
		return ServiceClient{}, lti.NewError(lti.ErrorInvalidToken, "the access token is unknown or expired", nil)
	}

	return ServiceClient{ClientID: "client-1", Scopes: granted}, nil
}

func (s *assetProcessorServer) getAsset(_ *http.Request, _ ServiceClient, assetID string) (AssetDownload, error) {
	download, ok := s.assets[assetID]
	if !ok {
		return AssetDownload{}, fmt.Errorf("looking up %q: %w", assetID, ErrAssetNotFound)
	}

	if download.RedirectURL == "" && download.ContentType != "" {
		download.Body = trackedBody{Reader: strings.NewReader("%PDF-1.7 the essay"), closed: &s.closed}
	}

	return download, nil
}

func (s *assetProcessorServer) postReport(_ *http.Request, _ ServiceClient, processorID string, report lti.Report) error {
	if !s.processors[processorID] {
		return ErrAssetProcessorNotFound
	}

	s.reports = append(s.reports, report)

	return nil
}

func (s *assetProcessorServer) deployment(deploymentID string) error {
	if !s.deployments[deploymentID] {
		return fmt.Errorf("looking up %q: %w", deploymentID, ErrDeploymentNotFound)
	}

	return nil
}

func (s *assetProcessorServer) recordAcceptance(_ *http.Request, _ ServiceClient, deploymentID string, acceptance lti.EulaAcceptance) error {
	if err := s.deployment(deploymentID); err != nil {
		return err
	}

	s.acceptances = append(s.acceptances, acceptance)

	return nil
}

func (s *assetProcessorServer) clearAcceptances(_ *http.Request, _ ServiceClient, deploymentID string) error {
	if err := s.deployment(deploymentID); err != nil {
		return err
	}

	s.cleared = append(s.cleared, deploymentID)

	return nil
}

func (s *assetProcessorServer) setRequired(_ *http.Request, _ ServiceClient, deploymentID string, required bool) error {
	if err := s.deployment(deploymentID); err != nil {
		return err
	}

	s.required = append(s.required, required)

	return nil
}

func (s *assetProcessorServer) handlers() Handlers {
	return Handlers{
		Register:             granting(&[]string{}),
		AuthorizeService:     s.authorize,
		GetAsset:             s.getAsset,
		PostReport:           s.postReport,
		RecordEulaAcceptance: s.recordAcceptance,
		ClearEulaAcceptances: s.clearAcceptances,
		SetEulaRequired:      s.setRequired,
	}
}

func createAssetProcessorTestConfig() Config {
	cfg := createTestConfig()
	cfg.AssetProcessor = true
	cfg.Paths.Assets = "/assets"
	cfg.Paths.AssetReports = "/asset-reports"
	cfg.Paths.Eula = "/eula"

	return cfg
}

func newAssetProcessorTestHandler(t *testing.T, s *assetProcessorServer) http.Handler {
	t.Helper()

	handler, err := NewHandler(createAssetProcessorTestConfig(), s.handlers())
	require.NoError(t, err)

	return handler
}

// ============================================================================
// Tests
// ============================================================================

func TestNewHandler_AssetProcessorServices_Authorize(t *testing.T) {
	t.Parallel()

	endpoints := []struct {
		name, method, target, body string
		scope                      lti.Scope
	}{
		{"asset", http.MethodGet, assetURL, "", lti.ScopeAssetReadOnly},
		{"report", http.MethodPost, assetReportURL, validReport, lti.ScopeReport},
		{"eula acceptance", http.MethodPost, eulaServiceURL + "/user", validAcceptance, lti.ScopeEulaUser},
		{"eula clear", http.MethodDelete, eulaServiceURL + "/user", "", lti.ScopeEulaUser},
		{"eula deployment", http.MethodPut, eulaServiceURL + "/deployment", validEulaSetting, lti.ScopeEulaDeployment},
	}

	for _, endpoint := range endpoints {
		t.Run(endpoint.name+" without a token", func(t *testing.T) {
			t.Parallel()

			w := callAGS(t, newAssetProcessorTestHandler(t, newAssetProcessorServer()), endpoint.method, endpoint.target, "", endpoint.body)
			require.Equal(t, http.StatusUnauthorized, w.Code)
			assert.Equal(t, "Bearer", w.Header().Get("WWW-Authenticate"))
		})

		t.Run(endpoint.name+" with an unknown token", func(t *testing.T) {
			t.Parallel()

			w := callAGS(t, newAssetProcessorTestHandler(t, newAssetProcessorServer()), endpoint.method, endpoint.target, "token-unknown", endpoint.body)
			requireAGSError(t, w, http.StatusUnauthorized, lti.ErrorInvalidToken, "")
			assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
		})

		t.Run(endpoint.name+" without its scope", func(t *testing.T) {
			t.Parallel()

			s := newAssetProcessorServer()
			// Every scope but the endpoint's own.
			for _, scope := range s.tokens["token-all"] {
				if scope != endpoint.scope {
					s.tokens["token-other"] = append(s.tokens["token-other"], scope)
				}
			}

			w := callAGS(t, newAssetProcessorTestHandler(t, s), endpoint.method, endpoint.target, "token-other", endpoint.body)
			requireAGSError(t, w, http.StatusForbidden, lti.ErrorInsufficientScope, "")
			assert.Equal(t, `Bearer error="insufficient_scope", scope="`+string(endpoint.scope)+`"`, w.Header().Get("WWW-Authenticate"))
			assert.Empty(t, s.reports)
			assert.Empty(t, s.acceptances)
			assert.Empty(t, s.cleared)
			assert.Empty(t, s.required)
		})

		t.Run(endpoint.name+" with only its scope", func(t *testing.T) {
			t.Parallel()

			s := newAssetProcessorServer()
			s.tokens["token-one"] = []lti.Scope{endpoint.scope}

			w := callAGS(t, newAssetProcessorTestHandler(t, s), endpoint.method, endpoint.target, "token-one", endpoint.body)
			assert.Less(t, w.Code, 300, w.Body.String())
		})
	}
}

func TestNewHandler_GetAsset(t *testing.T) {
	t.Parallel()

	t.Run("streams the bytes with the asset's content type", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodGet, assetURL, "token-all", "")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/pdf", w.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
		assert.Contains(t, w.Header().Get("Content-Security-Policy"), "sandbox")
		assert.Equal(t, "%PDF-1.7 the essay", w.Body.String())
		assert.Equal(t, 1, s.closed)
	})

	t.Run("sends the size as Content-Length", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		download := s.assets["asset-1"]
		download.Size = int64(len("%PDF-1.7 the essay"))
		s.assets["asset-1"] = download

		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodGet, assetURL, "token-all", "")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "18", w.Header().Get("Content-Length"))
	})

	t.Run("answers HEAD without the bytes", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodHead, assetURL, "token-all", "")

		require.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "application/pdf", w.Header().Get("Content-Type"))
		assert.Empty(t, w.Body.String())
		assert.Equal(t, 1, s.closed)
	})

	t.Run("redirects to where the bytes are", func(t *testing.T) {
		t.Parallel()

		w := callAGS(t, newAssetProcessorTestHandler(t, newAssetProcessorServer()), http.MethodGet, "https://platform.example.com/lti/assets/asset-redirect", "token-all", "")

		require.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t, "https://storage.example.com/asset-1?signature=abc", w.Header().Get("Location"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	})

	t.Run("answers an unknown asset with a 404", func(t *testing.T) {
		t.Parallel()

		w := callAGS(t, newAssetProcessorTestHandler(t, newAssetProcessorServer()), http.MethodGet, "https://platform.example.com/lti/assets/asset-2", "token-all", "")
		requireAGSError(t, w, http.StatusNotFound, lti.ErrorInvalidRequest, "the asset is unknown")
	})

	t.Run("serves only GET", func(t *testing.T) {
		t.Parallel()

		w := callAGS(t, newAssetProcessorTestHandler(t, newAssetProcessorServer()), http.MethodPost, assetURL, "token-all", "{}")
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("refuses what GetAsset should not return", func(t *testing.T) {
		t.Parallel()

		for name, download := range map[string]AssetDownload{
			"neither a body nor a redirect": {Body: nil, ContentType: "application/pdf", Size: 0, RedirectURL: ""},
			"both a body and a redirect":    {Body: io.NopCloser(strings.NewReader("x")), ContentType: "application/pdf", Size: 0, RedirectURL: "https://storage.example.com/a"},
			"an http redirect":              {Body: nil, ContentType: "", Size: 0, RedirectURL: "http://storage.example.com/a"},
			"a relative redirect":           {Body: nil, ContentType: "", Size: 0, RedirectURL: "/a"},
			"a body without a content type": {Body: io.NopCloser(strings.NewReader("x")), ContentType: "", Size: 0, RedirectURL: ""},
		} {
			s := newAssetProcessorServer()
			handlers := s.handlers()
			handlers.GetAsset = func(*http.Request, ServiceClient, string) (AssetDownload, error) { return download, nil }

			var reported []error

			handlers.OnError = func(_ *http.Request, err error) { reported = append(reported, err) }

			handler, err := NewHandler(createAssetProcessorTestConfig(), handlers)
			require.NoError(t, err)

			w := callAGS(t, handler, http.MethodGet, assetURL, "token-all", "")
			assert.Equal(t, http.StatusInternalServerError, w.Code, name)
			assert.Len(t, reported, 1, name)
		}
	})

	t.Run("answers a failing hook with a 500 that says nothing more", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		handlers := s.handlers()
		handlers.GetAsset = func(*http.Request, ServiceClient, string) (AssetDownload, error) {
			return AssetDownload{}, errors.New("storage is down")
		}

		handler, err := NewHandler(createAssetProcessorTestConfig(), handlers)
		require.NoError(t, err)

		w := callAGS(t, handler, http.MethodGet, assetURL, "token-all", "")
		assert.Equal(t, http.StatusInternalServerError, w.Code)
		assert.NotContains(t, w.Body.String(), "storage")
	})
}

func TestNewHandler_PostReport(t *testing.T) {
	t.Parallel()

	t.Run("saves the report and answers with it", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodPost, assetReportURL, "token-all", validReport)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.JSONEq(t, validReport, w.Body.String())

		require.Len(t, s.reports, 1)
		assert.Equal(t, lti.Report{
			AssetID: "asset-1", Type: "originality", Timestamp: time.Date(2026, 11, 10, 12, 0, 0, 123456000, time.UTC), Title: "",
			Result: "12%", Comment: "", IndicationColor: "", IndicationAlt: "", Priority: 2, VisibleToOwner: false,
			ProcessingProgress: lti.ProcessingProgressProcessed, ErrorCode: "", Extensions: nil,
		}, s.reports[0])
	})

	t.Run("answers an unknown processor with a 404", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodPost, "https://platform.example.com/lti/asset-reports/processor-2", "token-all", validReport)
		requireAGSError(t, w, http.StatusNotFound, lti.ErrorInvalidRequest, "the asset processor is unknown")
	})

	t.Run("refuses a body that isn't a report", func(t *testing.T) {
		t.Parallel()

		for body, description := range map[string]string{
			`not json`:                "the report is not a JSON object",
			`[]`:                      "the report is not a JSON object",
			`null`:                    "the report is not a JSON object",
			`{"assetId": 1}`:          "the report's assetId is not valid",
			`{"type": "originality"}`: "the report's assetId is missing",
			`{"assetId": "asset-1"}`:  "the report's type is missing",
			strings.Replace(validReport, `"priority": 2`, `"priority": 6`, 1):                               "the report's priority must be an integer from 0 to 5",
			strings.Replace(validReport, `"priority": 2`, `"priority": 1.5`, 1):                             "the report's priority is not valid",
			strings.Replace(validReport, `"priority": 2`, `"priority": "2"`, 1):                             "the report's priority is not valid",
			strings.Replace(validReport, `"priority": 2,`, ``, 1):                                           "the report's priority is missing",
			strings.Replace(validReport, `, "processingProgress": "Processed"`, ``, 1):                      "the report's processingProgress is missing",
			strings.Replace(validReport, `"processingProgress": "Processed"`, `"processingProgress": 1`, 1): "the report's processingProgress is not valid",
			strings.Replace(validReport, `"2026-11-10T12:00:00.123456Z"`, `"yesterday"`, 1):                 "the report's timestamp is not valid",
			strings.Replace(validReport, `"2026-11-10T12:00:00.123456Z"`, `""`, 1):                          "the report's timestamp is missing",
			strings.Replace(validReport, `"result": "12%"`, `"visibleToOwner": "yes"`, 1):                   "the report's visibleToOwner is not valid",
		} {
			s := newAssetProcessorServer()
			w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodPost, assetReportURL, "token-all", body)
			requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidRequest, description)
			assert.Empty(t, s.reports, body)
		}
	})

	t.Run("refuses a report over its limit with a 413", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		body := strings.Replace(validReport, `"12%"`, `"`+strings.Repeat("x", maxReportBytes)+`"`, 1)

		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodPost, assetReportURL, "token-all", body)
		requireAGSError(t, w, http.StatusRequestEntityTooLarge, lti.ErrorInvalidRequest, "")
		assert.Empty(t, s.reports)
	})

	t.Run("passes a hook's rejection of the asset on", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		handlers := s.handlers()
		handlers.PostReport = func(*http.Request, ServiceClient, string, lti.Report) error {
			return lti.NewError(lti.ErrorInvalidRequest, "the asset is not the processor's", nil)
		}

		handler, err := NewHandler(createAssetProcessorTestConfig(), handlers)
		require.NoError(t, err)

		w := callAGS(t, handler, http.MethodPost, assetReportURL, "token-all", validReport)
		requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidRequest, "the asset is not the processor's")
	})
}

func TestNewHandler_EulaService(t *testing.T) {
	t.Parallel()

	t.Run("records an acceptance and answers with it", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodPost, eulaServiceURL+"/user", "token-all", validAcceptance)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.JSONEq(t, validAcceptance, w.Body.String())
		assert.Equal(t, []lti.EulaAcceptance{{UserID: "user-1", Accepted: true, Timestamp: time.Date(2026, 11, 10, 12, 0, 0, 123456000, time.UTC)}}, s.acceptances)
	})

	t.Run("records a decline", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodPost, eulaServiceURL+"/user", "token-all", strings.Replace(validAcceptance, "true", "false", 1))

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		require.Len(t, s.acceptances, 1)
		assert.False(t, s.acceptances[0].Accepted)
	})

	t.Run("clears every acceptance", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodDelete, eulaServiceURL+"/user", "token-all", "")

		require.Equal(t, http.StatusNoContent, w.Code, w.Body.String())
		assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		assert.Equal(t, []string{"deployment-1"}, s.cleared)
	})

	t.Run("sets whether the deployment requires the eula", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		w := callAGS(t, newAssetProcessorTestHandler(t, s), http.MethodPut, eulaServiceURL+"/deployment", "token-all", validEulaSetting)

		require.Equal(t, http.StatusOK, w.Code, w.Body.String())
		assert.JSONEq(t, validEulaSetting, w.Body.String())
		assert.Equal(t, []bool{false}, s.required)
	})

	t.Run("answers an unknown deployment with a 404", func(t *testing.T) {
		t.Parallel()

		s := newAssetProcessorServer()
		handler := newAssetProcessorTestHandler(t, s)
		other := "https://platform.example.com/lti/eula/deployment-2"

		requireAGSError(t, callAGS(t, handler, http.MethodPost, other+"/user", "token-all", validAcceptance), http.StatusNotFound, lti.ErrorInvalidRequest, "the deployment is unknown")
		requireAGSError(t, callAGS(t, handler, http.MethodDelete, other+"/user", "token-all", ""), http.StatusNotFound, lti.ErrorInvalidRequest, "the deployment is unknown")
		requireAGSError(t, callAGS(t, handler, http.MethodPut, other+"/deployment", "token-all", validEulaSetting), http.StatusNotFound, lti.ErrorInvalidRequest, "the deployment is unknown")
	})

	t.Run("has nothing to read", func(t *testing.T) {
		t.Parallel()

		handler := newAssetProcessorTestHandler(t, newAssetProcessorServer())

		for _, target := range []string{eulaServiceURL + "/user", eulaServiceURL + "/deployment"} {
			assert.Equal(t, http.StatusMethodNotAllowed, callAGS(t, handler, http.MethodGet, target, "token-all", "").Code, target)
		}

		assert.Equal(t, http.StatusNotFound, callAGS(t, handler, http.MethodGet, eulaServiceURL, "token-all", "").Code)
	})

	t.Run("refuses a body without its members", func(t *testing.T) {
		t.Parallel()

		for _, tt := range []struct{ target, body, description string }{
			{eulaServiceURL + "/user", `{"accepted": true, "timestamp": "2026-11-10T12:00:00Z"}`, "the acceptance's userId is missing"},
			{eulaServiceURL + "/user", `{"userId": "user-1", "timestamp": "2026-11-10T12:00:00Z"}`, "the acceptance's accepted is missing"},
			{eulaServiceURL + "/user", `{"userId": "user-1", "accepted": true}`, "the acceptance's timestamp is missing"},
			{eulaServiceURL + "/user", `{"userId": "user-1", "accepted": "yes", "timestamp": "2026-11-10T12:00:00Z"}`, "the acceptance's accepted is not valid"},
			{eulaServiceURL + "/user", `[]`, "the acceptance is not a JSON object"},
			{eulaServiceURL + "/deployment", `{}`, "the eula deployment setting's eulaRequired is missing"},
			{eulaServiceURL + "/deployment", `{"eulaRequired": "false"}`, "the eula deployment setting's eulaRequired is not valid"},
		} {
			s := newAssetProcessorServer()
			method := http.MethodPost
			if strings.HasSuffix(tt.target, "/deployment") {
				method = http.MethodPut
			}

			w := callAGS(t, newAssetProcessorTestHandler(t, s), method, tt.target, "token-all", tt.body)
			requireAGSError(t, w, http.StatusBadRequest, lti.ErrorInvalidRequest, tt.description)
			assert.Empty(t, s.acceptances, tt.body)
			assert.Empty(t, s.required, tt.body)
		}
	})
}

func TestNewHandler_AssetProcessorServicesNeedTheirPathsAndHooks(t *testing.T) {
	t.Parallel()

	for name, change := range map[string]func(cfg *Config, h *Handlers){
		"assets path without GetAsset":           func(_ *Config, h *Handlers) { h.GetAsset = nil },
		"GetAsset without the assets path":       func(cfg *Config, _ *Handlers) { cfg.Paths.Assets = "" },
		"reports path without PostReport":        func(_ *Config, h *Handlers) { h.PostReport = nil },
		"PostReport without the reports path":    func(cfg *Config, _ *Handlers) { cfg.Paths.AssetReports = "" },
		"eula path without SetEulaRequired":      func(_ *Config, h *Handlers) { h.SetEulaRequired = nil },
		"eula path without ClearEulaAcceptances": func(_ *Config, h *Handlers) { h.ClearEulaAcceptances = nil },
		"eula hooks without the eula path":       func(cfg *Config, _ *Handlers) { cfg.Paths.Eula = "" },
		"the services without AuthorizeService":  func(_ *Config, h *Handlers) { h.AuthorizeService = nil },
	} {
		cfg := createAssetProcessorTestConfig()
		handlers := newAssetProcessorServer().handlers()
		change(&cfg, &handlers)

		_, err := NewHandler(cfg, handlers)
		require.Error(t, err, name)
	}

	for name, keep := range map[string]func(cfg *Config, h *Handlers){
		"only the asset service": func(cfg *Config, h *Handlers) {
			cfg.Paths.AssetReports, cfg.Paths.Eula = "", ""
			h.PostReport, h.RecordEulaAcceptance, h.ClearEulaAcceptances, h.SetEulaRequired = nil, nil, nil, nil
		},
		"only the asset report service": func(cfg *Config, h *Handlers) {
			cfg.Paths.Assets, cfg.Paths.Eula = "", ""
			h.GetAsset, h.RecordEulaAcceptance, h.ClearEulaAcceptances, h.SetEulaRequired = nil, nil, nil, nil
		},
		"only the eula service": func(cfg *Config, h *Handlers) {
			cfg.Paths.Assets, cfg.Paths.AssetReports = "", ""
			h.GetAsset, h.PostReport = nil, nil
		},
	} {
		cfg := createAssetProcessorTestConfig()
		handlers := newAssetProcessorServer().handlers()
		keep(&cfg, &handlers)

		_, err := NewHandler(cfg, handlers)
		require.NoError(t, err, name)
	}
}

func TestConfig_AssetProcessorServiceURLs(t *testing.T) {
	t.Parallel()

	cfg := createAssetProcessorTestConfig()

	asset, err := cfg.AssetURL("asset 1/a")
	require.NoError(t, err)
	assert.Equal(t, "https://platform.example.com/lti/assets/asset%201%2Fa", asset)

	report, err := cfg.AssetReportURL("processor-1")
	require.NoError(t, err)
	assert.Equal(t, assetReportURL, report)

	eula, err := cfg.EulaService("deployment-1")
	require.NoError(t, err)
	assert.Equal(t, lti.EulaService{URL: eulaServiceURL, Scopes: []lti.Scope{lti.ScopeEulaUser, lti.ScopeEulaDeployment}}, eula)

	for _, id := range []string{"", ".", ".."} {
		_, err = cfg.AssetURL(id)
		require.Error(t, err)
		_, err = cfg.AssetReportURL(id)
		require.Error(t, err)
		_, err = cfg.EulaServiceURL(id)
		require.Error(t, err)
	}

	none := createTestConfig()
	_, err = none.AssetURL("asset-1")
	require.Error(t, err)
	_, err = none.AssetReportURL("processor-1")
	require.Error(t, err)
	_, err = none.EulaService("deployment-1")
	require.Error(t, err)
}

func TestConfig_Validate_AssetProcessorServicePaths(t *testing.T) {
	t.Parallel()

	require.NoError(t, createAssetProcessorTestConfig().Validate())

	for name, change := range map[string]func(cfg *Config){
		"assets path with a trailing slash":       func(cfg *Config) { cfg.Paths.Assets = "/assets/" },
		"asset reports path another endpoint has": func(cfg *Config) { cfg.Paths.AssetReports = cfg.Paths.JWKS },
		"the same path for two services":          func(cfg *Config) { cfg.Paths.Eula = cfg.Paths.Assets },
		"a service path under another's":          func(cfg *Config) { cfg.Paths.AssetReports = "/assets/reports" },
		"another service's path under one":        func(cfg *Config) { cfg.Paths.NoticeHandlers = "/eula/notices" },
		"a context path under one":                func(cfg *Config) { cfg.Paths.ContextMemberships = "/assets/contexts" },
	} {
		cfg := createAssetProcessorTestConfig()
		change(&cfg)
		require.Error(t, cfg.Validate(), name)
	}
}

func TestConfig_OpenIDConfiguration_ListsTheScopesOfTheServicesItServes(t *testing.T) {
	t.Parallel()

	cfg := createAssetProcessorTestConfig()
	cfg.Scopes = []lti.Scope{lti.ScopeAGSScore, lti.ScopeReport}

	configuration, err := cfg.OpenIDConfiguration()
	require.NoError(t, err)

	assert.Equal(t, []string{
		"openid",
		string(lti.ScopeAGSScore),
		string(lti.ScopeReport),
		string(lti.ScopeAssetReadOnly),
		string(lti.ScopeEulaUser),
		string(lti.ScopeEulaDeployment),
	}, configuration.ScopesSupported)

	cfg.Paths.Assets, cfg.Paths.AssetReports, cfg.Paths.Eula = "", "", ""
	cfg.Scopes = nil

	configuration, err = cfg.OpenIDConfiguration()
	require.NoError(t, err)
	assert.Equal(t, []string{"openid"}, configuration.ScopesSupported)

	body, err := json.Marshal(configuration)
	require.NoError(t, err)
	assert.NotContains(t, string(body), "asset.readonly")
}
