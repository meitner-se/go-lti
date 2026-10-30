package platform_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"time"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/jwks"
	"github.com/meitner-se/go-lti/platform"
)

// exampleConfig is how a platform describes itself. Every value is the platform's own choice.
var exampleConfig = platform.Config{
	Issuer:        "https://lms.example.com/lti",
	Paths:         platform.Paths{Authorization: "/authorize", JWKS: "/jwks", Registration: "/register", DeepLinkReturn: "/deep-link-return"},
	TokenEndpoint: "https://lms.example.com/oauth/token",
	Product:       platform.Product{GUID: "lms-1", Name: "Example LMS", FamilyCode: "example-lms", Version: "1.0.0"},
}

// A launch is three requests: the platform sends the browser to the tool, the tool sends it back
// with an authentication request, and the platform answers with a signed id_token.
func Example_launch() {
	// Load the key from secret storage with lti.ParseRSAPrivateKeyPEM; generated here for the example.
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	keys, err := lti.StaticKeys(lti.SigningKey{ID: "key-1", Signer: privateKey})
	if err != nil {
		log.Fatal(err)
	}

	launcher, err := platform.NewLauncher(exampleConfig, keys)
	if err != nil {
		log.Fatal(err)
	}

	tool := platform.Tool{
		ClientID:         "client-1",
		InitiateLoginURI: "https://tool.example.com/lti/login",
		RedirectURIs:     []string{"https://tool.example.com/lti/launch"},
		TargetLinkURI:    "https://tool.example.com/lti/launch",
	}

	// 1. Where the user clicks. The hints are opaque: the platform decides what they are.
	initiation := platform.LoginInitiation{DeploymentID: "deployment-1", LoginHint: "user-1", MessageHint: "launch-1"}

	loginURL, err := exampleConfig.LoginInitiationURL(tool, initiation)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(loginURL)

	// 2. At Endpoints().Authorization, the tool's request comes back.
	req, err := platform.ParseAuthenticationRequest(url.Values{
		"scope": {"openid"}, "response_type": {"id_token"}, "response_mode": {"form_post"}, "prompt": {"none"},
		"client_id": {"client-1"}, "redirect_uri": {"https://tool.example.com/lti/launch"},
		"login_hint": {"user-1"}, "lti_message_hint": {"launch-1"}, "nonce": {"n-0S6_WzA2Mj"}, "state": {"af0ifjsldkj"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 3. Redeem req.MessageHint for the launch it stands for, including the login initiation it
	// sent, check that the logged-in user is the one login_hint stands for, then answer.
	form, err := launcher.Respond(context.Background(), req, platform.Launch{
		Tool:       tool,
		Initiation: initiation,
		Message: &lti.ResourceLinkRequest{
			Common: lti.Common{
				DeploymentID: "deployment-1",
				Subject:      "a6d5c443-1f51-4783-ba1a-7686ffe3b54a",
				Roles:        []lti.Role{lti.RoleLearner},
				Context:      &lti.LaunchContext{ID: "course-1", Title: "Biology 1"},
				// As configured on the link: the launch sends "course-1" for "$Context.id".
				Custom: map[string]string{"course": "$Context.id"},
			},
			ResourceLink: lti.ResourceLink{ID: "link-1", Title: "Quiz"},
		},
	})
	if err != nil {
		// For a rejection, launcher.RespondError(req, tool, err) returns the form that tells the tool.
		log.Fatal(err)
	}

	// form.ServeHTTP(w, r) writes the page that posts id_token and state to the tool.
	fmt.Println(form.Action, form.Fields[0].Name, form.Fields[1].Name)

	// Output:
	// https://tool.example.com/lti/login?client_id=client-1&iss=https%3A%2F%2Flms.example.com%2Flti&login_hint=user-1&lti_deployment_id=deployment-1&lti_message_hint=launch-1&target_link_uri=https%3A%2F%2Ftool.example.com%2Flti%2Flaunch
	// https://tool.example.com/lti/launch id_token state
}

// A tool registers itself; the admin reviews what it asks for before anything goes live.
func Example_registration() {
	body := []byte(`{
		"response_types": ["id_token"],
		"grant_types": ["implicit", "client_credentials"],
		"initiate_login_uri": "https://tool.example.com/lti/login",
		"redirect_uris": ["https://tool.example.com/lti/launch"],
		"client_name": "Quiz Tool",
		"client_name#sv": "Quizverktyg",
		"jwks_uri": "https://tool.example.com/.well-known/jwks.json",
		"token_endpoint_auth_method": "private_key_jwt",
		"scope": "https://purl.imsglobal.org/spec/lti-ags/scope/score",
		"https://purl.imsglobal.org/spec/lti-tool-configuration": {
			"domain": "tool.example.com",
			"target_link_uri": "https://tool.example.com/lti/launch",
			"claims": ["iss", "sub", "email"],
			"messages": [{"type": "LtiDeepLinkingRequest", "label": "Add a quiz"}]
		}
	}`)

	reg, err := platform.ParseRegistration(body)
	if err != nil {
		// A rejection is an *lti.Error; answer with its StatusCode, Code and Description.
		log.Fatal(err)
	}

	review := reg.Review(exampleConfig)
	fmt.Println(review.ClientName, review.ClientNames["sv"])
	fmt.Println("asks for email:", review.RequestsEmail)
	fmt.Println("unsupported scopes:", review.UnsupportedScopes)

	// Once an admin approves, register the tool and answer with what was granted.
	response := reg.Response(platform.RegistrationGrant{ClientID: "client-1", DeploymentID: "deployment-1", Claims: []string{"iss", "sub"}})
	fmt.Println(response.ClientID, response.ToolConfiguration.Claims)

	// Output:
	// Quiz Tool Quizverktyg
	// asks for email: true
	// unsupported scopes: [https://purl.imsglobal.org/spec/lti-ags/scope/score]
	// client-1 [iss sub]
}

// The OpenID configuration document is served at the URL a platform hands tools in Dynamic Registration.
func ExampleConfig_OpenIDConfiguration() {
	configuration, err := exampleConfig.OpenIDConfiguration()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(configuration.Issuer)
	fmt.Println(configuration.TokenEndpoint)

	// Output:
	// https://lms.example.com/lti
	// https://lms.example.com/oauth/token
}

// A tool posts its Deep Linking response to the platform's return URL.
func Example_deepLinking() {
	fetcher, err := jwks.NewFetcher()
	if err != nil {
		log.Fatal(err)
	}

	verifier, err := platform.NewDeepLinkingVerifier(exampleConfig, fetcher, &exampleNonceStore{used: map[string]time.Time{}})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /lti/deep-link-return", func(w http.ResponseWriter, r *http.Request) {
		// Load what the platform sent from its own state for this browser, such as the record behind
		// the session cookie. Never build it from the posted JWT: that is read before it is verified.
		session := platform.DeepLinkingSession{
			Tool: platform.Tool{
				ClientID: "client-1",
				JWKSURI:  "https://tool.example.com/.well-known/jwks.json",
				Domains:  []string{"tool.example.com"},
			},
			DeploymentID: "deployment-1",
			Settings: lti.DeepLinkingSettings{
				AcceptTypes:                       []lti.ContentItemType{lti.ContentItemTypeLTIResourceLink},
				AcceptPresentationDocumentTargets: []lti.DocumentTarget{lti.DocumentTargetIframe},
				Data:                              "request-1",
			},
		}

		response, err := verifier.Verify(r.Context(), r.PostFormValue(lti.DeepLinkingResponseField), session)
		if rejection, ok := lti.AsError(err); ok {
			http.Error(w, rejection.Description, rejection.StatusCode())

			return
		}

		if err != nil {
			http.Error(w, "the tool's response could not be checked", http.StatusBadGateway)

			return
		}

		fmt.Fprintf(w, "added %d items", len(response.Items))
	})
}

// NewHandler serves the Deep Linking return itself: it looks the request up by the response's
// unverified claims, verifies the response against what the platform stored, and hands over the
// result.
func ExampleNewHandler_deepLinkReturn() {
	fetcher, err := jwks.NewFetcher()
	if err != nil {
		log.Fatal(err)
	}

	// The platform's own record of each Deep Linking request it sent, by its data value.
	requests := map[string]platform.DeepLinkingSession{}

	handler, err := platform.NewHandler(exampleConfig, platform.Handlers{
		Register: func(context.Context, string, *platform.Registration) (platform.RegistrationGrant, error) {
			return platform.RegistrationGrant{}, lti.NewError(lti.ErrorInvalidToken, "registration is closed", nil)
		},
		ToolKeys: fetcher,
		// Only right for a single replica; see MemoryNonceStore.
		Nonces: lti.NewMemoryNonceStore(),
		FindDeepLinkingSession: func(_ *http.Request, unverified platform.UnverifiedDeepLinkingResponse) (platform.DeepLinkingSession, error) {
			session, ok := requests[unverified.Data]
			if !ok || session.Tool.ClientID != unverified.Issuer {
				return platform.DeepLinkingSession{}, platform.ErrDeepLinkingSessionNotFound
			}

			return session, nil
		},
		HandleDeepLinkingResponse: func(w http.ResponseWriter, r *http.Request, result platform.DeepLinkingResult) {
			// Mark the request answered, save result.Response.Items or record result.Err, then send
			// the user back to where they started.
			w.Header().Set("Cache-Control", "no-store")
			http.Redirect(w, r, "https://lms.example.com/courses/1", http.StatusSeeOther)
		},
	})
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(exampleConfig.Endpoints().DeepLinkReturn, handler != nil)
	// Output: https://lms.example.com/lti/deep-link-return true
}

// A tool launched with a context_memberships_url reads the context's members there with its access
// token (Names and Role Provisioning Services 2.0). The platform answers with a page of members,
// and links the next page while there is one.
func ExampleAddMembershipLinks() {
	// The launch tells the tool where the context's members are.
	_ = &lti.ResourceLinkRequest{
		Common: lti.Common{
			DeploymentID:          "deployment-1",
			Subject:               "user-1",
			Context:               &lti.LaunchContext{ID: "course-1"},
			ContextMembershipsURL: "https://lms.example.com/lti/contexts/course-1/memberships",
		},
		ResourceLink: lti.ResourceLink{ID: "link-1"},
	}

	// The memberships endpoint, after checking the tool's access token and the context.
	membershipsHandler := func(w http.ResponseWriter, _ *http.Request) {
		page := lti.MembershipContainer{
			ID:      "https://lms.example.com/lti/contexts/course-1/memberships?limit=1",
			Context: lti.MembershipContext{ID: "course-1"},
			Members: []lti.Member{{Status: lti.MembershipStatusActive, UserID: "user-1", Roles: []lti.Role{lti.RoleLearner}}},
		}

		if err := platform.AddMembershipLinks(w.Header(), "https://lms.example.com/lti/contexts/course-1/memberships?limit=1&page=2", ""); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)

			return
		}

		w.Header().Set("Content-Type", lti.MembershipContainerMediaType)

		if err := json.NewEncoder(w).Encode(page); err != nil {
			log.Print(err)
		}
	}

	w := httptest.NewRecorder()
	membershipsHandler(w, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "https://lms.example.com/lti/contexts/course-1/memberships?limit=1", http.NoBody))

	fmt.Println(w.Header().Get("Content-Type"))
	fmt.Println(w.Header().Get("Link"))
	fmt.Print(w.Body.String())

	// Output:
	// application/vnd.ims.lti-nrps.v2.membershipcontainer+json
	// <https://lms.example.com/lti/contexts/course-1/memberships?limit=1&page=2>; rel="next"
	// {"id":"https://lms.example.com/lti/contexts/course-1/memberships?limit=1","context":{"id":"course-1"},"members":[{"status":"Active","user_id":"user-1","roles":["http://purl.imsglobal.org/vocab/lis/v2/membership#Learner"]}]}
}

// exampleNonceStore keeps used nonces in memory. A real platform keeps them where every replica
// can see them, such as a table or Redis, until they expire.
type exampleNonceStore struct {
	mu   sync.Mutex
	used map[string]time.Time
}

func (s *exampleNonceStore) Claim(_ context.Context, issuer, nonce string, expiresAt time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	key := issuer + "\x00" + nonce
	if until, ok := s.used[key]; ok && time.Now().Before(until) {
		return false, nil
	}

	s.used[key] = expiresAt

	return true, nil
}
