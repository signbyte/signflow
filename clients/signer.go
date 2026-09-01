package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Signer is the client for the signing provider — the service that owns the
// trust-service session, the redirect dance, certificate selection, and signature
// finalization. signflow only routes, polls, and reconciles through it; it holds
// no provider credentials and no provider session.
type Signer struct {
	doer     Doer
	baseURL  string
	audience string
}

// NewSigner builds a signing-provider client over the given outbound doer.
func NewSigner(d Doer, baseURL, audience string) *Signer {
	return &Signer{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

const (
	scopeSignCreate = "signatures:create"
	scopeSignWrite  = "signatures:write"
	scopeSignRead   = "signatures:read"
)

// slowOpTimeout is the per-call ceiling for validate and archive-timestamp —
// operations whose upstream work legitimately runs tens of seconds (a
// long-term-archival validation checks the archive-timestamp chain plus
// long-term revocation material, ~16–40s observed; the provider's own upstream
// hop is 30s with one retry). It must comfortably outlast that worst case —
// the default service-call timeout is tuned for fast calls and abandons these
// mid-flight while they go on to succeed.
const slowOpTimeout = 90 * time.Second

// PrepareDoc is one document in a prepare request. For hash-only XAdES only the
// digest is sent — the bytes never leave the document service.
type PrepareDoc struct {
	DocumentID      string `json:"documentId"`
	FileName        string `json:"fileName"`
	MimeType        string `json:"mimeType,omitempty"`
	DocumentHash    string `json:"documentHash,omitempty"`
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
	SignatureFormat string `json:"signatureFormat"`
	// FileRef names the multipart file part carrying this document's bytes, for the
	// byte-conduit prepare (PAdES embeds the signature in the document, so it has no
	// hash-only mode and the whole document must transit). Empty for hash-only XAdES,
	// which sends DocumentHash instead.
	FileRef string `json:"fileRef,omitempty"`
	// Operation is the provider's create-vs-parallel hint (a first signature vs a
	// co-signature). Optional — omitted for formats/paths where the provider derives it.
	Operation string `json:"operation,omitempty"`
	// Files carries the inner data objects when the document being signed is itself
	// an ASiC-E container — the signature is then a parallel co-signature over all
	// of them (one provider session, N file digests). Empty for a normal document,
	// which uses DocumentHash instead.
	Files []PrepareFile `json:"files,omitempty"`
}

// PrepareFile is one inner data object of a container being co-signed: the
// in-container filename and its digest.
type PrepareFile struct {
	Name            string `json:"name"`
	Digest          string `json:"digest"`
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
}

// PrepareOptions carries the optional inputs to a prepare call beyond the
// documents themselves. The card certificates are sent only for the in-browser
// flow; the redirect URLs are sent only for the redirect flows, where the provider
// returns the browser to PostAuthRedirect after authorization succeeds (or
// AuthErrorRedirect on failure), substituting the job id for a "{jobId}"
// placeholder so the portal recovers the job without holding client state.
type PrepareOptions struct {
	SigningCertificate string
	AuthCertificate    string
	// SignIdentityID names the provider-side sign identity the certificates
	// belong to (a caller's login-captured identity); SealID picks which seal
	// signs (the e-seal flow when the person holds several). Both optional.
	SignIdentityID    string
	SealID            string
	PostAuthRedirect  string
	AuthErrorRedirect string
}

type prepareRequest struct {
	Documents []PrepareDoc `json:"documents"`
	// SigningCertificate and AuthCertificate are the card certificates for the
	// in-browser flow: the signing certificate lets the provider compute the
	// per-document digest the card will sign, and the authentication certificate is
	// used when the signature is finalized. Both are public certificates (not
	// secrets) and are omitted for the redirect flows, which read their own.
	SigningCertificate string `json:"signingCertificate,omitempty"`
	AuthCertificate    string `json:"authCertificate,omitempty"`
	// SignIdentityID and SealID: the caller-supplied identity pass-throughs
	// (see PrepareOptions).
	SignIdentityID string `json:"signIdentityId,omitempty"`
	SealID         string `json:"sealId,omitempty"`
	// PostAuthRedirect and AuthErrorRedirect carry the redirect flow's return URLs,
	// omitted for the in-browser flow.
	PostAuthRedirect  string `json:"postAuthRedirect,omitempty"`
	AuthErrorRedirect string `json:"authErrorRedirect,omitempty"`
}

// DocRef is a per-document element of a prepare or status response.
type DocRef struct {
	DocumentID      string `json:"documentId"`
	Digest          string `json:"digest,omitempty"`
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
	State           string `json:"state,omitempty"`
	DownloadURL     string `json:"downloadUrl,omitempty"`
}

type authorization struct {
	AuthorizeURL string `json:"authorizeUrl"`
}

// PrepareResult is the provider's prepare response. For remote flows it carries an
// authorization the user must visit; for the in-browser flow it carries the
// per-document digest the client signs.
type PrepareResult struct {
	JobID         string         `json:"jobId"`
	Flow          string         `json:"flow"`
	State         string         `json:"state"`
	Authorization *authorization `json:"authorization,omitempty"`
	SignAlgorithm string         `json:"signAlgorithm,omitempty"`
	Documents     []DocRef       `json:"documents,omitempty"`
}

// AuthorizeURL returns the redirect URL for remote flows, or "" when none.
func (p *PrepareResult) AuthorizeURL() string {
	if p.Authorization == nil {
		return ""
	}

	return p.Authorization.AuthorizeURL
}

// StatusResult is the provider's reconciled job status. VerificationCode,
// VerificationMessage + SigningDeadline are published by the device-push flow
// (eID Scan) while the provider waits for the user to confirm on their phone —
// the code and prompt the portal shows so the user can match them against what
// the app displays.
type StatusResult struct {
	JobID               string   `json:"jobId"`
	Flow                string   `json:"flow"`
	State               string   `json:"state"`
	VerificationCode    string   `json:"verificationCode,omitempty"`
	VerificationMessage string   `json:"verificationMessage,omitempty"`
	SigningDeadline     int64    `json:"signingDeadline,omitempty"`
	Documents           []DocRef `json:"documents"`
}

// ClientSignature is one client-produced signature value (the in-browser flow).
type ClientSignature struct {
	DocumentID     string `json:"documentId"`
	SignatureValue string `json:"signatureValue"`
}

type submitRequest struct {
	Signatures []ClientSignature `json:"signatures"`
}

// Prepare begins a signing job on the provider for the given flow. The in-browser
// flow supplies the card certificates via opts; the redirect flows supply the
// return URLs.
func (s *Signer) Prepare(ctx context.Context, flow string, docs []PrepareDoc, opts PrepareOptions) (*PrepareResult, error) {
	body, err := json.Marshal(prepareRequest{
		Documents:          docs,
		SigningCertificate: opts.SigningCertificate,
		AuthCertificate:    opts.AuthCertificate,
		SignIdentityID:     opts.SignIdentityID,
		SealID:             opts.SealID,
		PostAuthRedirect:   opts.PostAuthRedirect,
		AuthErrorRedirect:  opts.AuthErrorRedirect,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: marshal prepare: %w", err)
	}

	url := s.baseURL + "/api/v1/signatures/prepare?flow=" + flow

	var out PrepareResult
	if err := doJSON(ctx, s.doer, "signer", s.audience, scopeSignCreate, http.MethodPost, url, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// PrepareWithFile begins a byte-conduit signing job: the document bytes are sent as
// multipart file parts (each doc's FileRef names its part) alongside the JSON
// metadata. Used for PAdES, which embeds the signature in the document and so has no
// hash-only path — the whole document transits the provider transiently (not
// retained here).
func (s *Signer) PrepareWithFile(ctx context.Context, flow string, docs []PrepareDoc, files map[string][]byte, opts PrepareOptions) (*PrepareResult, error) {
	meta, err := json.Marshal(prepareRequest{
		Documents:          docs,
		SigningCertificate: opts.SigningCertificate,
		AuthCertificate:    opts.AuthCertificate,
		SignIdentityID:     opts.SignIdentityID,
		SealID:             opts.SealID,
		PostAuthRedirect:   opts.PostAuthRedirect,
		AuthErrorRedirect:  opts.AuthErrorRedirect,
	})
	if err != nil {
		return nil, fmt.Errorf("signer: marshal prepare metadata: %w", err)
	}

	body, contentType, err := multipartMetaFiles("metadata", string(meta), files)
	if err != nil {
		return nil, fmt.Errorf("signer: build prepare multipart: %w", err)
	}

	url := s.baseURL + "/api/v1/signatures/prepare?flow=" + flow

	var out PrepareResult
	if err := doJSON(ctx, s.doer, "signer", s.audience, scopeSignCreate, http.MethodPost, url, body, contentType, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Status fetches the reconciled job status, optionally long-polling up to wait
// seconds (the provider holds the connection until the state changes or the
// window elapses).
func (s *Signer) Status(ctx context.Context, jobID string, wait int) (*StatusResult, error) {
	url := fmt.Sprintf("%s/api/v1/signatures/%s/status", s.baseURL, jobID)
	if wait > 0 {
		url += fmt.Sprintf("?wait=%d", wait)
	}

	var out StatusResult
	if err := doJSON(ctx, s.doer, "signer", s.audience, scopeSignRead, http.MethodGet, url, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Submit hands the client-produced signature value(s) to the provider (the
// in-browser flow). The response carries the resulting job state.
func (s *Signer) Submit(ctx context.Context, jobID string, sigs []ClientSignature) (*StatusResult, error) {
	body, err := json.Marshal(submitRequest{Signatures: sigs})
	if err != nil {
		return nil, fmt.Errorf("signer: marshal submit: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/signatures/%s/signatures", s.baseURL, jobID)

	var out StatusResult
	if err := doJSON(ctx, s.doer, "signer", s.audience, scopeSignWrite, http.MethodPost, url, body, "application/json", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Validate uploads an already-signed container to the provider and returns its
// validation report bytes verbatim — the provider relays the upstream report
// unchanged, so the report shape is the provider's, not signflow's. signflow
// normalizes it into the portal's field set; this client does not interpret it.
func (s *Signer) Validate(ctx context.Context, container []byte, filename string) ([]byte, error) {
	if filename == "" {
		filename = "container.asice"
	}

	body, contentType, err := multipartFile("file", filename, container)
	if err != nil {
		return nil, fmt.Errorf("signer: build validate multipart: %w", err)
	}

	url := s.baseURL + "/api/v1/validations"

	hdr := http.Header{}
	hdr.Set("Content-Type", contentType)

	resp, err := s.doer.DoServiceWithTimeout(ctx, slowOpTimeout, s.audience, scopeSignRead, http.MethodPost, url, hdr, body)
	if err != nil {
		return nil, fmt.Errorf("signer: validate: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Service: "signer", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}

	return resp.Body, nil
}

// Archive uploads an already-signed document to the provider's archive-timestamp
// endpoint and returns the archived bytes — the same document refreshed to its
// long-term archival form (an ARCHIVE_TIMESTAMP embedded in each signature).
// Like Validate, the provider picks its processing path from the filename
// extension, so the caller supplies one matching the document form.
func (s *Signer) Archive(ctx context.Context, signed []byte, filename, authCert string) ([]byte, error) {
	if filename == "" {
		filename = "container.asice"
	}

	// The timestamp request is made in the acting user's name: their
	// authentication certificate rides along (a public certificate,
	// request-scoped — never held or logged).
	fields := map[string]string{}
	if authCert != "" {
		fields["authCertificate"] = authCert
	}
	body, contentType, err := multipartFileFields("file", filename, signed, fields)
	if err != nil {
		return nil, fmt.Errorf("signer: build archive multipart: %w", err)
	}

	url := s.baseURL + "/api/v1/archive-timestamps"

	hdr := http.Header{}
	hdr.Set("Content-Type", contentType)

	resp, err := s.doer.DoServiceWithTimeout(ctx, slowOpTimeout, s.audience, scopeSignWrite, http.MethodPost, url, hdr, body)
	if err != nil {
		return nil, fmt.Errorf("signer: archive: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Service: "signer", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}

	return resp.Body, nil
}

// Download fetches the signed document bytes for a completed signature. For
// hash-only XAdES the provider returns a fileless ASiC-E container (it never held
// the source bytes; the document service injects those during completion) —
// requested with container=asice. For PAdES the provider returns the complete
// signed PDF, so no container form is requested.
func (s *Signer) Download(ctx context.Context, jobID, docID, sigFormat string) ([]byte, error) {
	url := fmt.Sprintf("%s/api/v1/signatures/%s/documents/%s", s.baseURL, jobID, docID)
	if sigFormat != "PAdES" { // PAdES downloads the signed PDF as-is; everything else is an ASiC-E container
		url += "?container=asice"
	}

	resp, err := s.doer.DoService(ctx, s.audience, scopeSignRead, http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("signer: download: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Service: "signer", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}

	return resp.Body, nil
}
