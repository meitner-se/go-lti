package platform_test

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/jwks"
	"github.com/meitner-se/go-lti/platform"
)

// exampleConfig is how a platform describes itself. Every value is the platform's own choice.
var exampleConfig = platform.Config{
	Issuer: "https://lms.example.com/lti",
	Endpoints: platform.Endpoints{
		Authorization:  "https://lms.example.com/lti/authorize",
		JWKS:           "https://lms.example.com/lti/jwks",
		Registration:   "https://lms.example.com/lti/register",
		Token:          "https://lms.example.com/oauth/token",
		DeepLinkReturn: "https://lms.example.com/lti/deep-link-return",
	},
	Product: platform.Product{GUID: "lms-1", Name: "Example LMS", FamilyCode: "example-lms", Version: "1.0.0"},
}

// A tool registers itself; the admin reviews what it asks for before anything goes live.
func Example_registration() {
	body := []byte(`{
		"response_types": ["id_token"],
		"grant_types": ["implicit", "client_credentials"],
		"initiate_login_uri": "https://tool.example.com/lti/login",
		"redirect_uris": ["https://tool.example.com/lti/launch"],
		"client_name": "Quiz Tool",
		"client_name#fr": "Outil de quiz",
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
	fmt.Println(review.ClientName, review.ClientNames["fr"])
	fmt.Println("asks for email:", review.RequestsEmail)
	fmt.Println("unsupported scopes:", review.UnsupportedScopes)

	// Once an admin approves, register the tool and answer with what was granted.
	response := reg.Response(platform.RegistrationGrant{ClientID: "client-1", DeploymentID: "deployment-1", Claims: []string{"iss", "sub"}})
	fmt.Println(response.ClientID, response.ToolConfiguration.Claims)

	// Output:
	// Quiz Tool Outil de quiz
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
	verifier, err := platform.NewDeepLinkingVerifier(exampleConfig, jwks.NewFetcher(), exampleNonceStore{})
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("POST /lti/deep-link-return", func(w http.ResponseWriter, r *http.Request) {
		// Look up what the platform sent in the request, such as by its data claim.
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

// exampleNonceStore stands in for a store shared by every replica, such as a table or Redis.
type exampleNonceStore struct{}

func (exampleNonceStore) Claim(context.Context, string, string, time.Time) (bool, error) {
	return true, nil
}
