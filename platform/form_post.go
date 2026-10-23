package platform

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"html/template"
	"net/http"
)

// formPostScript submits the form as soon as the page loads. The CSP allows only this script.
const formPostScript = `document.forms[0].submit();`

var (
	formPostScriptHash = func() string {
		digest := sha256.Sum256([]byte(formPostScript))

		return "sha256-" + base64.StdEncoding.EncodeToString(digest[:])
	}()

	formPostCSP = "default-src 'none'; script-src '" + formPostScriptHash + "'; form-action https:; base-uri 'none'"

	formPostTemplate = template.Must(template.New("form_post").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><meta name="referrer" content="no-referrer"><title>Continue</title></head>
<body>
<form method="post" action="{{.Action}}">
{{- range .Fields}}
<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{- end}}
<noscript><button type="submit">Continue</button></noscript>
</form>
<script>` + formPostScript + `</script>
</body>
</html>
`))
)

// FormField is one hidden field of a FormPost.
type FormField struct {
	Name  string
	Value string
}

// FormPost is an auto-submitting form that posts fields to a tool, as OAuth 2.0 Form Post Response
// Mode requires.
type FormPost struct {
	Action string
	Fields []FormField
}

// ServeHTTP writes the form page. It sets Cache-Control: no-store, so the id_token isn't kept,
// Referrer-Policy: no-referrer, and a Content-Security-Policy that allows only the page's own
// inline script, by hash. The form submits by itself, or with a button when scripts are off.
func (f *FormPost) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	var page bytes.Buffer
	if err := formPostTemplate.Execute(&page, f); err != nil {
		http.Error(w, "the response could not be written", http.StatusInternalServerError)

		return
	}

	header := w.Header()
	header.Set("Content-Type", "text/html; charset=utf-8")
	header.Set("Cache-Control", "no-store")
	header.Set("Pragma", "no-cache")
	header.Set("Referrer-Policy", "no-referrer")
	header.Set("X-Content-Type-Options", "nosniff")
	header.Set("Content-Security-Policy", formPostCSP)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(page.Bytes()) //nolint:errcheck // the response has started; there is nothing left to report a write error to
}
