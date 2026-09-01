// Package clients holds the outbound HTTP clients signflow uses to conduct a
// signing: the signing provider (prepare / status / submit / download) and the
// document service (metadata / container completion). Provider calls go out as
// signflow's own DPoP service identity; document calls go out on behalf of the
// signing user (the document is the user's, owner-filtered by the document
// service), via token exchange. Both are issued through the shared auth client;
// tests inject a stub doer.
package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// Doer issues a background DPoP request — as signflow's own service identity
// (DoService) or on behalf of an end user via token exchange (DoServiceOnBehalf).
// DoServiceWithTimeout carries a per-call overall timeout for operations that
// legitimately outlast the client's default ceiling (a long-term-archival
// validation runs tens of seconds upstream). *authclient.Client satisfies it;
// tests inject a stub.
type Doer interface {
	DoService(ctx context.Context, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
	DoServiceWithTimeout(ctx context.Context, timeout time.Duration, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
	DoServiceOnBehalf(ctx context.Context, audience, scope, subjectSub, subjectToken, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error)
}

// OnBehalf carries the end-user identity a document call acts for: the user's
// subject (the delegated-token cache key) and the raw inbound token to exchange.
// The document service authorizes on the user (owner-by-subject or, for an invited
// co-signer, their eIDAS serial against the chain ACL), so a call without a subject
// token cannot reach a user-owned document — the document client fails closed
// rather than falling back to signflow's own service identity.
type OnBehalf struct {
	Sub   string
	Token string
}

// HTTPError is returned when a collaborator responds with a non-2xx status; it
// carries the status so callers can map it onto their own response.
type HTTPError struct {
	Service    string
	StatusCode int
	Body       string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s: upstream status %d: %s", e.Service, e.StatusCode, e.Body)
}

// doJSON issues a request and, when out is non-nil, decodes the JSON response into
// it. A non-2xx status is returned as *HTTPError. contentType is set only when the
// request carries a body.
func doJSON(ctx context.Context, d Doer, service, audience, scope, method, url string, reqBody []byte, contentType string, out any) error {
	hdr := http.Header{}
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}

	resp, err := d.DoService(ctx, audience, scope, method, url, hdr, reqBody)
	if err != nil {
		return fmt.Errorf("%s: %w", service, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Service: service, StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("%s: decode response: %w", service, err)
		}
	}

	return nil
}

// doJSONOnBehalf is doJSON acting on behalf of the end user (obo): it exchanges
// the user's token for a delegated one so the callee owner-filters on the user.
// It fails closed when no subject token is present.
func doJSONOnBehalf(ctx context.Context, d Doer, service, audience, scope, method, url string, obo OnBehalf, reqBody []byte, contentType string, out any) error {
	if obo.Token == "" {
		return fmt.Errorf("%s: missing on-behalf-of subject token", service)
	}

	hdr := http.Header{}
	if contentType != "" {
		hdr.Set("Content-Type", contentType)
	}

	resp, err := d.DoServiceOnBehalf(ctx, audience, scope, obo.Sub, obo.Token, method, url, hdr, reqBody)
	if err != nil {
		return fmt.Errorf("%s: %w", service, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return &HTTPError{Service: service, StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}
	if out != nil && len(resp.Body) > 0 {
		if err := json.Unmarshal(resp.Body, out); err != nil {
			return fmt.Errorf("%s: decode response: %w", service, err)
		}
	}

	return nil
}
