package platform

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/meitner-se/go-lti"
	"github.com/meitner-se/go-lti/internal/jose"
	"github.com/meitner-se/go-lti/safehttp"
)

// NoticeTTL is how long a notice JWT is valid. The platform signs a notice just before it posts it,
// and signs it again for every resend.
const NoticeTTL = 5 * time.Minute

// noticeHTTPTimeout bounds a post of notices with the default client.
const noticeHTTPTimeout = 30 * time.Second

// maxNoticeResponseBytes is how much of a handler's answer is read, so the connection can be reused.
const maxNoticeResponseBytes = 64 << 10

// Notice is a notice the platform sends a tool with the LTI Platform Notification Service: an event
// in a deployment, such as a submission. The platform keeps it and its data stable across resends;
// each send signs a new notice JWT, with a new iat, exp and nonce.
type Notice struct {
	// DeploymentID is the deployment the notice is for. At most 255 characters.
	DeploymentID string
	// ID is the notice's id, unique for ever within the deployment, and the same on every resend so
	// that the tool can drop duplicates. At most 255 characters.
	ID string
	// Type is the notice's type, one of Config.NoticeTypes.
	Type lti.NoticeType
	// Timestamp is when the event happened. Its time zone is sent with it.
	Timestamp time.Time
	// Subject is the sub of the user the notice is about, as in launches to the same tool, if any.
	// At most 255 characters.
	Subject string
	// Context is the context the notice is about, if any.
	Context *lti.LaunchContext
	// Custom are custom parameters for the tool, if any, sent as they are: notices don't substitute
	// variables.
	Custom map[string]string
	// Claims are the notice type's own claims, such as an asset or a submission. They may not
	// override a claim the package sets.
	Claims []lti.Claim
}

// SignNotice returns notice as a notice JWT for tool, signed with the platform's key: iss, aud,
// iat, exp, nonce, the LTI version, deployment_id, the notice claim, tool_platform, and sub,
// context and custom when the notice has them. Each call signs a new JWT, with a new iat, exp and
// nonce, as a resend needs. A notice that is incomplete or breaks the spec's limits is an error.
func (l *Launcher) SignNotice(ctx context.Context, tool Tool, notice Notice) (string, error) {
	nonce, err := newNonce()
	if err != nil {
		return "", err
	}

	claims, err := l.noticeClaims(tool, notice, nonce, l.now())
	if err != nil {
		return "", err
	}

	key, err := l.keys.SigningKey(ctx)
	if err != nil {
		return "", fmt.Errorf("lti: cannot get signing key: %w", err)
	}

	public, err := key.PublicKey()
	if err != nil {
		return "", err
	}

	token, err := jose.SignRS256(public.ID, key.Signer, claims)
	if err != nil {
		return "", fmt.Errorf("lti: cannot sign notice: %w", err)
	}

	return token, nil
}

// noticeClaims lays notice out as the claims of a notice JWT for tool, issued at now.
func (l *Launcher) noticeClaims(tool Tool, notice Notice, nonce string, now time.Time) (map[string]any, error) {
	switch {
	case tool.ClientID == "":
		return nil, errors.New("lti: notice needs the tool's client_id")
	case notice.DeploymentID == "" || len(notice.DeploymentID) > maxIdentifierLength:
		return nil, errors.New("lti: notice needs a deployment_id of at most 255 characters")
	case notice.ID == "" || len(notice.ID) > maxIdentifierLength:
		return nil, errors.New("lti: notice needs an id of at most 255 characters")
	case notice.Type == "":
		return nil, errors.New("lti: notice needs a type")
	case notice.Timestamp.IsZero():
		return nil, errors.New("lti: notice needs the timestamp of its event")
	case len(notice.Subject) > maxIdentifierLength:
		return nil, errors.New("lti: notice sub must be at most 255 characters")
	case notice.Context != nil && (notice.Context.ID == "" || len(notice.Context.ID) > maxIdentifierLength):
		return nil, errors.New("lti: notice context needs an id of at most 255 characters")
	}

	claims := map[string]any{
		"iss":                 l.config.Issuer,
		"aud":                 tool.ClientID,
		"iat":                 now.Unix(),
		"exp":                 now.Add(NoticeTTL).Unix(),
		"nonce":               nonce,
		lti.ClaimVersion:      lti.Version,
		lti.ClaimDeploymentID: notice.DeploymentID,
		lti.ClaimNotice:       lti.Notice{ID: notice.ID, Timestamp: notice.Timestamp, Type: notice.Type},
		lti.ClaimToolPlatform: toolPlatformClaim(l.config.Product),
	}

	setIfNotEmpty(claims, "sub", notice.Subject)

	if notice.Context != nil {
		claims[lti.ClaimContext] = *notice.Context
	}

	if len(notice.Custom) > 0 {
		claims[lti.ClaimCustom] = notice.Custom
	}

	for _, claim := range notice.Claims {
		if claim == nil {
			return nil, errors.New("lti: a notice claim is nil")
		}

		name := claim.ClaimName()
		if !strings.Contains(name, "://") || reservedClaims[name] {
			return nil, fmt.Errorf("lti: notice claim %q must be a fully qualified url that the package doesn't set", name)
		}

		if _, ok := claims[name]; ok {
			return nil, fmt.Errorf("lti: notice claim %q is set twice", name)
		}

		claims[name] = claim
	}

	return claims, nil
}

// newNonce returns a random nonce, unique to each notice JWT.
func newNonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("lti: cannot make a nonce: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NoticeDeliveryError is what PostNotices returns when a handler answers with a status other than
// 2xx. The platform decides whether to send again: a 404 or 410 may mean the handler is gone.
type NoticeDeliveryError struct {
	StatusCode int
}

func (e *NoticeDeliveryError) Error() string {
	return fmt.Sprintf("lti: the notice handler answered %d", e.StatusCode)
}

// defaultNoticeClient posts notices when PostNotices gets no client.
var defaultNoticeClient = sync.OnceValue(func() *http.Client { return safehttp.NewClient(noticeHTTPTimeout) })

// PostNotices posts envelope to a tool's notice handler, as application/json. The handler is a URL
// the tool controls, so client should come from safehttp.NewClient; nil uses one with a 30 second
// timeout. All the envelope's notices must be of the handler's notice type, and no more of them
// than the tool's max_batch_size.
//
// A 2xx answer is a delivery. Any other status is a *NoticeDeliveryError, and a failure to connect
// is the client's error. Delivery is at least once: to send again, sign each notice again with
// SignNotice and post a new envelope.
func PostNotices(ctx context.Context, client *http.Client, handler string, envelope lti.NoticeEnvelope) error {
	if len(envelope.Notices) == 0 {
		return errors.New("lti: a notice envelope needs at least one notice")
	}

	u, err := url.Parse(handler)
	if err != nil || safehttp.CheckURL(u) != nil {
		return errors.New("lti: a notice handler must be an absolute https url without credentials")
	}

	body, err := json.Marshal(envelope) //nolint:errchkjson // errcheck requires the check outside _test.go files
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")

	if client == nil {
		client = defaultNoticeClient()
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("lti: cannot post notices: %w", err)
	}

	// Drain the answer so the connection can be reused; nothing in it matters.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxNoticeResponseBytes)) //nolint:errcheck // the status is the answer
	_ = resp.Body.Close()                                                         //nolint:errcheck // the status is the answer

	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &NoticeDeliveryError{StatusCode: resp.StatusCode}
	}

	return nil
}
