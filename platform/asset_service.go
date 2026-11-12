package platform

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/urlcheck"
)

// ErrAssetNotFound is what GetAsset returns, or wraps, for an asset that doesn't exist or that the
// tool may not download, such as one never sent to it. The tool gets a 404 with OAuth 2.0's error
// response.
var ErrAssetNotFound = lti.NewError(lti.ErrorInvalidRequest, "the asset is unknown", nil)

// AssetDownload is an asset as GetAsset returns it: either its bytes, which go-lti streams to the
// tool, or where the tool downloads them instead. Set Body or RedirectURL, not both.
type AssetDownload struct {
	// Body is the asset's bytes. go-lti streams them to the tool and closes Body.
	Body io.ReadCloser
	// ContentType is the asset's media type, the content_type the assetservice claim sent the tool,
	// and the answer's Content-Type. Required with Body.
	ContentType string
	// Size is the asset's size in bytes, sent as Content-Length when it is greater than 0. Body must
	// then have exactly that many bytes.
	Size int64
	// RedirectURL is where the tool downloads the asset instead, an absolute https URL, such as a
	// signed URL to the platform's storage. go-lti answers 302 Found to it, and the tool follows it
	// without its access token.
	RedirectURL string
}

// getAsset answers a tool's GET of an asset, for a token granted lti.ScopeAssetReadOnly: the bytes
// GetAsset returns with the asset's Content-Type, or a 302 to where it says they are.
func (e *endpoints) getAsset(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeAssetReadOnly

	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return
	}

	assetID := r.PathValue("asset")
	if !isPathSegment(assetID) {
		e.failAssetProcessor(w, r, scope, ErrAssetNotFound)

		return
	}

	download, err := e.handlers.GetAsset(r, client, assetID)
	if download.Body != nil {
		defer func() {
			if err := download.Body.Close(); err != nil {
				e.report(r, err)
			}
		}()
	}

	if err == nil {
		err = checkAssetDownload(download)
	}

	if err != nil {
		e.failAssetProcessor(w, r, scope, err)

		return
	}

	if download.RedirectURL != "" {
		http.Redirect(w, r, download.RedirectURL, http.StatusFound)

		return
	}

	header := w.Header()
	header.Set("Content-Type", download.ContentType)
	// The bytes are a user's upload: never let a browser run or sniff them.
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", "default-src 'none'; sandbox")

	if download.Size > 0 {
		header.Set("Content-Length", strconv.FormatInt(download.Size, 10))
	}

	w.WriteHeader(http.StatusOK)

	if r.Method == http.MethodHead {
		return
	}

	if _, err := io.Copy(w, download.Body); err != nil {
		// The answer has started, so the tool sees a cut-off body; only the platform can be told.
		e.report(r, err)
	}
}

// checkAssetDownload checks that GetAsset returned a body with a media type or an https redirect.
func checkAssetDownload(download AssetDownload) error {
	switch {
	case (download.Body == nil) == (download.RedirectURL == ""):
		return errors.New("lti: GetAsset must return either a body or a redirect url")
	case download.RedirectURL != "" && !urlcheck.IsHTTPS(download.RedirectURL):
		return errors.New("lti: GetAsset's redirect url must be an absolute https url")
	case download.Body != nil:
		if _, _, err := mime.ParseMediaType(download.ContentType); err != nil {
			return errors.New("lti: GetAsset must return the asset's content type with its body")
		}
	}

	return nil
}

// failAssetProcessor answers ErrAssetNotFound, ErrAssetProcessorNotFound and ErrDeploymentNotFound
// with a 404, and any other error as failService does.
func (e *endpoints) failAssetProcessor(w http.ResponseWriter, r *http.Request, scope lti.Scope, err error) {
	for _, target := range []*lti.Error{ErrAssetNotFound, ErrAssetProcessorNotFound, ErrDeploymentNotFound} {
		if errors.Is(err, target) {
			e.report(r, err)
			writeErrorResponse(w, http.StatusNotFound, target)

			return
		}
	}

	e.failService(w, r, scope, err)
}
