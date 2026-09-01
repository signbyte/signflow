package routes

import "azugo.io/azugo"

// createSigningRequest is the body of POST /api/v1/signings.
type createSigningRequest struct {
	EnvelopeID string `json:"envelopeId" validate:"required"`
	SlotID     string `json:"slotId" validate:"required"`
	Flow       string `json:"flow" validate:"required,oneof=webEid eidScan eparakstsMobile eparakstsMobileEseal csc"`
	SigFormat  string `json:"sigFormat" validate:"required,oneof=PAdES XAdES"`
	// DocumentID is the document to sign. Until the Envelope/Workflow service can
	// resolve slot → document, the caller supplies it directly.
	DocumentID string `json:"documentId" validate:"required"`
	// SigningCertificate and AuthCertificate carry certificates for the signing
	// act: the card certificates for the in-browser (webEid) flow — required
	// there — or the caller's login-captured identity certificates for a
	// redirect flow, letting the provider skip its own identity resolution.
	// Public certificates — request-scoped, never persisted or logged.
	SigningCertificate string `json:"signingCertificate"`
	AuthCertificate    string `json:"authCertificate"`
	// SignIdentityID names the provider-side sign identity the certificates
	// belong to (optional; pairs with the certificates above).
	SignIdentityID string `json:"signIdentityId"`
	// SealID picks which seal signs (the e-seal flow when the person holds
	// several; optional).
	SealID string `json:"sealId"`
	// PostAuthRedirect and AuthErrorRedirect are the URLs the provider sends the
	// browser back to after a redirect flow's authorization completes or fails. A
	// "{jobId}" placeholder is substituted with this job's id so the portal can
	// recover the job on return without holding client state. Empty for the
	// in-browser flow, which never leaves the page.
	PostAuthRedirect  string `json:"postAuthRedirect"`
	AuthErrorRedirect string `json:"authErrorRedirect"`
}

// Validate implements azugo.Validator (ctx.Body.JSON auto-validates).
func (r *createSigningRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// clientSignatureValue is one client-produced signature.
type clientSignatureValue struct {
	DocumentID     string `json:"documentId" validate:"required"`
	SignatureValue string `json:"signatureValue" validate:"required"`
}

// clientSignatureRequest is the body of POST /api/v1/signings/{jobId}/client-signature.
type clientSignatureRequest struct {
	Signatures []clientSignatureValue `json:"signatures" validate:"required,min=1,dive"`
}

// Validate implements azugo.Validator.
func (r *clientSignatureRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// digestRef is one per-document digest the in-browser client must sign.
type digestRef struct {
	DocumentID      string `json:"documentId"`
	Digest          string `json:"digest"`
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
}

// signingResponse is the uniform signing-lifecycle response. authorizeUrl is set
// for remote flows that need a user redirect; signAlgorithm + documents are set for
// the in-browser flow (the digests to sign on the card); verificationCode,
// verificationMessage + signingDeadline are set during the device-push confirmation
// window (eID Scan) so the portal can show the code and prompt the user matches on
// their phone; containerId is set on completion.
type signingResponse struct {
	JobID               string      `json:"jobId"`
	State               string      `json:"state"`
	AuthorizeURL        string      `json:"authorizeUrl,omitempty"`
	SignAlgorithm       string      `json:"signAlgorithm,omitempty"`
	VerificationCode    string      `json:"verificationCode,omitempty"`
	VerificationMessage string      `json:"verificationMessage,omitempty"`
	SigningDeadline     int64       `json:"signingDeadline,omitempty"`
	Documents           []digestRef `json:"documents,omitempty"`
	ContainerID         string      `json:"containerId,omitempty"`
	SignatureID         string      `json:"signatureId,omitempty"`
}

// chainFreeResponse is the body of GET /api/v1/chain-free: whether the chain's
// active-signer lock is currently free (a blocked co-signer may proceed to sign).
type chainFreeResponse struct {
	Free bool `json:"free"`
}

// validateRequest is the body of POST /api/v1/validations: re-validate an
// already-recorded signature on demand.
type validateRequest struct {
	SignatureID string `json:"signatureId" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *validateRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// docValidateRequest is the body of POST /api/v1/document-validations: validate
// a signed document on demand (an uploaded already-signed file, or any signed
// head). Nothing is persisted — the answer is returned, not recorded.
type docValidateRequest struct {
	DocumentID string `json:"documentId" validate:"required"`
}

// Validate implements azugo.Validator.
func (r *docValidateRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// archiveRequest asks for a signed document's archive-timestamp refresh
// (B-LT → B-LTA). The document is the chain's signed head; the caller must be
// on its chain (the on-behalf read enforces it). AuthCertificate is the
// signed-in user's authentication certificate — the timestamp request is made
// in the acting user's name (public certificate, request-scoped, never logged).
type archiveRequest struct {
	DocumentID      string `json:"documentId" validate:"required"`
	AuthCertificate string `json:"authCertificate"`
}

// Validate implements azugo.Validator.
func (r *archiveRequest) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}

// archiveResponse is the refreshed head: the SAME document id, now pointing at
// the archive-timestamped bytes.
type archiveResponse struct {
	DocumentID  string `json:"documentId"`
	ContentHash string `json:"contentHash"`
	Mime        string `json:"mime"`
	Size        int64  `json:"size"`
}

// The validation answer's wire shape is the shared validation-answer
// library's Validation type (aliased as orchestrator.ValidationResult) — one
// normalized field set served by every consumer; the routes only add the
// caller context (signatureId / documentId).
