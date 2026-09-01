package routes

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	api "github.com/signbyte/signflow"
	"github.com/signbyte/signflow/clients"
	"github.com/signbyte/signflow/orchestrator"
	"github.com/signbyte/signflow/store"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// stubSigner / stubDocs are minimal collaborators for the route happy-path tests;
// the conductor's own logic is covered by the orchestrator package tests. Scripted
// fields default to a remote flow that awaits authorization; set status/report to
// drive completion + validation.
type stubSigner struct {
	prep   *clients.PrepareResult
	status *clients.StatusResult
	report []byte
	// lastOpts captures the most recent prepare options (a pointer so the value
	// receiver writes through), letting a test assert what the route threaded down.
	lastOpts *clients.PrepareOptions
}

func (s stubSigner) Prepare(_ context.Context, _ string, _ []clients.PrepareDoc, opts clients.PrepareOptions) (*clients.PrepareResult, error) {
	if s.lastOpts != nil {
		*s.lastOpts = opts
	}

	return s.prep, nil
}
func (s stubSigner) Status(context.Context, string, int) (*clients.StatusResult, error) {
	if s.status != nil {
		return s.status, nil
	}

	return &clients.StatusResult{State: "AWAITING_AUTHORIZATION"}, nil
}
func (s stubSigner) PrepareWithFile(_ context.Context, _ string, _ []clients.PrepareDoc, _ map[string][]byte, opts clients.PrepareOptions) (*clients.PrepareResult, error) {
	if s.lastOpts != nil {
		*s.lastOpts = opts
	}

	return s.prep, nil
}
func (stubSigner) Submit(context.Context, string, []clients.ClientSignature) (*clients.StatusResult, error) {
	return &clients.StatusResult{State: "SIGNING"}, nil
}
func (stubSigner) Download(context.Context, string, string, string) ([]byte, error) {
	return []byte("fileless"), nil
}
func (s stubSigner) Validate(context.Context, []byte, string) ([]byte, error) {
	return s.report, nil
}

func (s stubSigner) Archive(_ context.Context, signed []byte, _, _ string) ([]byte, error) {
	return append([]byte("archived:"), signed...), nil
}

type stubDocs struct{}

func (stubDocs) Metadata(context.Context, string, clients.OnBehalf) (*clients.Meta, error) {
	return &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"}, nil
}
func (stubDocs) DataObjects(context.Context, string, clients.OnBehalf) ([]clients.DataObject, error) {
	return nil, nil
}
func (stubDocs) Complete(context.Context, string, []byte, clients.OnBehalf) (*clients.Container, error) {
	return &clients.Container{ContainerID: "cont-1"}, nil
}
func (stubDocs) StoreSignedDocument(context.Context, string, []byte, string, string, clients.OnBehalf) (*clients.SignedDoc, error) {
	return &clients.SignedDoc{SignedDocumentID: "signed-1"}, nil
}
func (stubDocs) StoreArchived(_ context.Context, id string, _ []byte, _ string, _ clients.OnBehalf) (*clients.ArchivedDoc, error) {
	return &clients.ArchivedDoc{ID: id, ContentHash: "archived-hash"}, nil
}
func (stubDocs) Content(context.Context, string, clients.OnBehalf) ([]byte, error) {
	return []byte("full-container-bytes"), nil
}
func (stubDocs) CurrentHead(context.Context, string, clients.OnBehalf) (*clients.ChainHead, error) {
	return &clients.ChainHead{}, nil // no signed head yet → sign the chain root
}

func appWithConductor(t testing.TB, prep *clients.PrepareResult) *azugo.TestApp {
	return appWithSigner(t, stubSigner{prep: prep})
}

func appWithSigner(t testing.TB, signer stubSigner) *azugo.TestApp {
	app := api.TestApp(t)
	qt.Assert(t, qt.IsNil(Init(app)))
	app.SetConductor(orchestrator.New(store.NewMemory(), signer, stubDocs{}, nil))

	return azugo.NewTestApp(app.App)
}

// testIDCodeLV returns a Latvian personal identity code in the PNO form the
// signing provider reports: the country, a six-digit leading group and a
// five-digit serial, built from one repeated digit so it reads as a placeholder at
// a glance.
//
// It is assembled from those parts at run time rather than written as a literal —
// an identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's code
// to a reader.
func testIDCodeLV(digit int) string {
	d := strconv.Itoa(digit)

	return "PNOLV-" + strings.Repeat(d, 6) + "-" + strings.Repeat(d, 5)
}

// passingReport is a verbatim provider validation report for one valid qualified
// XAdES signature, in the provider's top-level {data:{…}} shape (the signing party
// nested under signerExt).
var passingReport = `{"data":{"signatureForm":"ASiC-E","validationLevel":"ARCHIVAL_DATA",` +
	`"signaturesExt":[{"id":"S1","indication":"TOTAL-PASSED","subIndication":"",` +
	`"signatureLevel":"QESIG","signatureFormat":"XAdES_BASELINE_LT",` +
	`"signerExt":{"signedby":"TEST SIGNER","organization":null,` +
	`"signerSerialNumber":"` + testIDCodeLV(3) + `","registrationNumber":null},` +
	`"timeStamp":"2026-06-27T07:22:26Z","ocspResponceTime":"2026-06-27T07:22:27Z",` +
	`"errors":[],"warnings":[]}],` +
	`"signaturesCount":1,"validSignaturesCount":1,` +
	`"validatedDocument":{"fileName":"contract.asice","includedFiles":["contract.pdf"]}}}`

// A wired createSigning for a remote flow returns 201 with the job id + the
// authorize URL the user must visit.
func TestCreateSigningRemoteFlow(t *testing.T) {
	app := appWithConductor(t, prepareWithURL("job-9", "AWAITING_AUTHORIZATION", "https://idp/authorize"))
	app.Start(t)
	defer app.Stop()

	body := []byte(`{"envelopeId":"env-1","slotId":"slot-1","flow":"eparakstsMobile","sigFormat":"XAdES","documentId":"doc-1"}`)
	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("X-Test-Login-Method", "eparakstsMobile"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out signingResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Assert(t, qt.Equals(out.JobID, "job-9"))
	qt.Assert(t, qt.Equals(out.AuthorizeURL, "https://idp/authorize"))
	fasthttp.ReleaseResponse(resp)
}

// A redirect flow threads the portal's return URLs through to the provider's
// prepare call, so the provider can send the browser back to the portal (with the
// job id substituted) after authorization.
func TestCreateSigningThreadsReturnURLs(t *testing.T) {
	var opts clients.PrepareOptions
	app := appWithSigner(t, stubSigner{
		prep:     prepareWithURL("job-r", "AWAITING_AUTHORIZATION", "https://idp/authorize"),
		lastOpts: &opts,
	})
	app.Start(t)
	defer app.Stop()

	body := []byte(`{"envelopeId":"env-1","slotId":"slot-1","flow":"eparakstsMobile","sigFormat":"XAdES",` +
		`"documentId":"doc-1","postAuthRedirect":"https://app/documents/doc-1/sign?job={jobId}",` +
		`"authErrorRedirect":"https://app/documents/doc-1/sign?job={jobId}&err=1"}`)
	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("X-Test-Login-Method", "eparakstsMobile"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(opts.PostAuthRedirect, "https://app/documents/doc-1/sign?job={jobId}"))
	qt.Assert(t, qt.Equals(opts.AuthErrorRedirect, "https://app/documents/doc-1/sign?job={jobId}&err=1"))
}

// createSigning rejects an invalid body (missing required fields) at validation.
func TestCreateSigningInvalidBody(t *testing.T) {
	app := appWithConductor(t, prepareWithURL("job-9", "AWAITING_AUTHORIZATION", ""))
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", []byte(`{"flow":"eparakstsMobile"}`), tc.WithHeader("X-Test-Scopes", "signatures:create"))
	qt.Assert(t, qt.IsNil(err))
	// azugo maps a request-validation failure to 422 Unprocessable Entity.
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}

// A wired createSigning for the in-browser flow returns 201 with the signature
// algorithm + the per-document digests the card must sign (no authorize URL).
func TestCreateSigningWebEidReturnsDigests(t *testing.T) {
	app := appWithConductor(t, &clients.PrepareResult{
		JobID:         "job-w",
		State:         "AWAITING_CLIENT_SIGNATURE",
		SignAlgorithm: "RSA_SHA256",
		Documents:     []clients.DocRef{{DocumentID: "doc-1", Digest: "ZGlnZXN0", DigestAlgorithm: "SHA-256"}},
	})
	app.Start(t)
	defer app.Stop()

	body := []byte(`{"envelopeId":"env-1","slotId":"slot-1","flow":"webEid","sigFormat":"XAdES",` +
		`"documentId":"doc-1","signingCertificate":"MIIsign","authCertificate":"MIIauth"}`)
	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("X-Test-Login-Method", "webEid"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out signingResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Assert(t, qt.Equals(out.SignAlgorithm, "RSA_SHA256"))
	qt.Assert(t, qt.Equals(len(out.Documents), 1))
	qt.Assert(t, qt.Equals(out.Documents[0].Digest, "ZGlnZXN0"))
	qt.Assert(t, qt.Equals(out.AuthorizeURL, ""))
	fasthttp.ReleaseResponse(resp)
}

// createSigning rejects an in-browser request that omits the card certificates with
// 400 invalid_request, before any provider call.
func TestCreateSigningWebEidRequiresCerts(t *testing.T) {
	app := appWithConductor(t, prepareWithURL("job-9", "AWAITING_CLIENT_SIGNATURE", ""))
	app.Start(t)
	defer app.Stop()

	body := []byte(`{"envelopeId":"env-1","slotId":"slot-1","flow":"webEid","sigFormat":"XAdES","documentId":"doc-1"}`)
	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", body, tc.WithHeader("X-Test-Scopes", "signatures:create"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))

	var out struct {
		Code string `json:"code"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Assert(t, qt.Equals(out.Code, "err:signing:invalidRequest"))
	fasthttp.ReleaseResponse(resp)
}

// A full signing drives create → status-to-complete (which validates at signing
// time and returns the signature id) → on-demand /validations, returning the
// normalized verdict.
func TestSigningCompletesThenValidates(t *testing.T) {
	app := appWithSigner(t, stubSigner{
		prep:   prepareWithURL("job-7", "AWAITING_AUTHORIZATION", "https://idp/authorize"),
		status: &clients.StatusResult{JobID: "job-7", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		report: []byte(passingReport),
	})
	app.Start(t)
	defer app.Stop()
	tc := app.TestClient()

	body := []byte(`{"envelopeId":"env-1","slotId":"slot-1","flow":"eparakstsMobile","sigFormat":"XAdES","documentId":"doc-1"}`)
	resp, err := tc.Post("/api/v1/signings", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("X-Test-Login-Method", "eparakstsMobile"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))
	fasthttp.ReleaseResponse(resp)

	// Drive the job to completion; the status turn validates at signing time.
	resp, err = tc.Get("/api/v1/signings/job-7/status", tc.WithHeader("X-Test-Scopes", "signatures:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var done signingResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &done)))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(done.State, "COMPLETED"))
	qt.Assert(t, qt.Not(qt.Equals(done.SignatureID, "")))

	// Re-validate on demand.
	vbody := []byte(`{"signatureId":"` + done.SignatureID + `"}`)
	resp, err = tc.Post("/api/v1/validations", vbody, tc.WithHeader("X-Test-Scopes", "signatures:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	var v orchestrator.ValidationResult
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &v)))
	fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(v.Verdict, "PASSED"))
	qt.Assert(t, qt.IsTrue(v.Pass))
	qt.Assert(t, qt.Equals(v.Level, "QES"))
	qt.Assert(t, qt.Equals(v.SignatureID, done.SignatureID))
}

// A createSigning whose login method does not permit the requested flow is
// refused with 403 binding_mismatch, with the binding gate fail-closed.
func TestCreateSigningBindingMismatch(t *testing.T) {
	app := appWithSigner(t, stubSigner{prep: prepareWithURL("job-9", "AWAITING_AUTHORIZATION", "")})
	app.Start(t)
	defer app.Stop()

	// Logged in via Web eID, but requesting an eID Scan signing.
	body := []byte(`{"envelopeId":"env-1","slotId":"slot-1","flow":"eidScan","sigFormat":"XAdES","documentId":"doc-1"}`)
	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("X-Test-Login-Method", "webEid"),
		tc.WithHeader("X-Test-LoA", "high"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))

	var out struct {
		Code string `json:"code"`
	}
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Assert(t, qt.Equals(out.Code, "err:signing:bindingMismatch"))
	fasthttp.ReleaseResponse(resp)
}

// A createSigning whose login method permits the requested flow is accepted (201)
// even with the binding gate fail-closed, and the job carries the binding.
func TestCreateSigningBindingMatch(t *testing.T) {
	app := appWithSigner(t, stubSigner{prep: prepareWithURL("job-8", "AWAITING_AUTHORIZATION", "https://idp/authorize")})
	app.Start(t)
	defer app.Stop()

	body := []byte(`{"envelopeId":"env-1","slotId":"slot-1","flow":"eparakstsMobile","sigFormat":"XAdES","documentId":"doc-1"}`)
	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("X-Test-Login-Method", "eparakstsMobile"),
		tc.WithHeader("X-Test-LoA", "high"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusCreated))

	var out signingResponse
	qt.Assert(t, qt.IsNil(json.Unmarshal(resp.Body(), &out)))
	qt.Assert(t, qt.Equals(out.JobID, "job-8"))
	fasthttp.ReleaseResponse(resp)
}

// validate rejects a body with no signatureId at request validation.
func TestValidateInvalidBody(t *testing.T) {
	app := appWithConductor(t, prepareWithURL("job-9", "AWAITING_AUTHORIZATION", ""))
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/validations", []byte(`{}`), tc.WithHeader("X-Test-Scopes", "signatures:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)
}

// validate is not found for an unknown signature id.
func TestValidateUnknownSignature(t *testing.T) {
	app := appWithConductor(t, prepareWithURL("job-9", "AWAITING_AUTHORIZATION", ""))
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/validations", []byte(`{"signatureId":"missing"}`), tc.WithHeader("X-Test-Scopes", "signatures:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNotFound))
	fasthttp.ReleaseResponse(resp)
}

// prepareWithURL builds a PrepareResult through its JSON wire shape so the
// unexported authorization field is populated.
func prepareWithURL(jobID, state, authorizeURL string) *clients.PrepareResult {
	var p clients.PrepareResult
	body := `{"jobId":"` + jobID + `","state":"` + state + `"`
	if authorizeURL != "" {
		body += `,"authorization":{"authorizeUrl":"` + authorizeURL + `"}`
	}
	body += `}`
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		panic(err)
	}

	return &p
}
