package platform

import (
	"encoding/json"
	"net/http"

	"github.com/meitner-se/go-lti"
)

// recordEulaAcceptance answers a tool's POST of a user's EULA acceptance to a deployment's EULA
// service, for a token granted lti.ScopeEulaUser. It hands the acceptance to RecordEulaAcceptance
// and answers 200 with the acceptance the tool sent.
func (e *endpoints) recordEulaAcceptance(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeEulaUser

	client, deploymentID, ok := e.eulaRequest(w, r, scope)
	if !ok {
		return
	}

	body, err := readServiceBytes(w, r, "acceptance", maxServiceBodyBytes)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	var acceptance lti.EulaAcceptance
	if err := json.Unmarshal(body, &acceptance); err != nil {
		e.failService(w, r, scope, objectRejection("acceptance", err))

		return
	}

	if err := e.handlers.RecordEulaAcceptance(r, client, deploymentID, acceptance); err != nil {
		e.failAssetProcessor(w, r, scope, err)

		return
	}

	writeJSON(w, http.StatusOK, body)
}

// clearEulaAcceptances answers a tool's DELETE of a deployment's EULA acceptances, for a token
// granted lti.ScopeEulaUser: it has ClearEulaAcceptances forget every user's and answers 204.
func (e *endpoints) clearEulaAcceptances(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeEulaUser

	client, deploymentID, ok := e.eulaRequest(w, r, scope)
	if !ok {
		return
	}

	if err := e.handlers.ClearEulaAcceptances(r, client, deploymentID); err != nil {
		e.failAssetProcessor(w, r, scope, err)

		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// setEulaRequired answers a tool's PUT of whether a deployment requires its EULA, for a token
// granted lti.ScopeEulaDeployment. It hands the setting to SetEulaRequired and answers 200 with the
// setting the tool sent.
func (e *endpoints) setEulaRequired(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	scope := lti.ScopeEulaDeployment

	client, deploymentID, ok := e.eulaRequest(w, r, scope)
	if !ok {
		return
	}

	body, err := readServiceBytes(w, r, "eula deployment setting", maxServiceBodyBytes)
	if err != nil {
		e.failService(w, r, scope, err)

		return
	}

	var setting lti.EulaDeployment
	if err := json.Unmarshal(body, &setting); err != nil {
		e.failService(w, r, scope, objectRejection("eula deployment setting", err))

		return
	}

	if err := e.handlers.SetEulaRequired(r, client, deploymentID, setting.EulaRequired); err != nil {
		e.failAssetProcessor(w, r, scope, err)

		return
	}

	writeJSON(w, http.StatusOK, body)
}

// eulaRequest authorizes a request to a deployment's EULA service for scope and reads the
// deployment id from its path. It answers a request it refuses itself and returns false.
func (e *endpoints) eulaRequest(w http.ResponseWriter, r *http.Request, scope lti.Scope) (ServiceClient, string, bool) {
	client, ok := e.authorizeService(w, r, scope)
	if !ok {
		return ServiceClient{}, "", false
	}

	deploymentID := r.PathValue("deployment")
	if !isPathSegment(deploymentID) {
		e.failAssetProcessor(w, r, scope, ErrDeploymentNotFound)

		return ServiceClient{}, "", false
	}

	return client, deploymentID, true
}
