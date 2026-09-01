package orchestrator

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"

	"github.com/signbyte/signflow/clients"
	"github.com/signbyte/signflow/store"
)

// fakeSigner records calls and returns scripted results.
type fakeSigner struct {
	prepare  *clients.PrepareResult
	status   *clients.StatusResult
	submit   *clients.StatusResult
	download []byte
	report   []byte

	prepareCalls, prepareFileCalls, statusCalls, submitCalls, downloadCalls, validateCalls int
	lastFlow                                                                               string
	lastPrepareDocs                                                                        []clients.PrepareDoc
	lastPrepareFiles                                                                       map[string][]byte
	lastDownloadFormat                                                                     string
	lastValidateFilename                                                                   string
	lastArchiveFilename                                                                    string
	lastSigningCert, lastAuthCert                                                          string
	lastSignIdentityID, lastSealID                                                         string
	lastArchiveAuthCert                                                                    string
	lastPostAuthRedirect, lastAuthErrorRedirect                                            string
}

func (f *fakeSigner) Prepare(_ context.Context, flow string, docs []clients.PrepareDoc, opts clients.PrepareOptions) (*clients.PrepareResult, error) {
	f.prepareCalls++
	f.lastFlow = flow
	f.lastPrepareDocs = docs
	f.lastSigningCert = opts.SigningCertificate
	f.lastAuthCert = opts.AuthCertificate
	f.lastSignIdentityID = opts.SignIdentityID
	f.lastSealID = opts.SealID
	f.lastPostAuthRedirect = opts.PostAuthRedirect
	f.lastAuthErrorRedirect = opts.AuthErrorRedirect

	return f.prepare, nil
}

func (f *fakeSigner) PrepareWithFile(_ context.Context, flow string, docs []clients.PrepareDoc, files map[string][]byte, opts clients.PrepareOptions) (*clients.PrepareResult, error) {
	f.prepareFileCalls++
	f.lastFlow = flow
	f.lastPrepareDocs = docs
	f.lastPrepareFiles = files
	f.lastSigningCert = opts.SigningCertificate
	f.lastAuthCert = opts.AuthCertificate
	f.lastSignIdentityID = opts.SignIdentityID
	f.lastSealID = opts.SealID
	f.lastPostAuthRedirect = opts.PostAuthRedirect
	f.lastAuthErrorRedirect = opts.AuthErrorRedirect

	return f.prepare, nil
}

func (f *fakeSigner) Status(_ context.Context, _ string, _ int) (*clients.StatusResult, error) {
	f.statusCalls++

	return f.status, nil
}

func (f *fakeSigner) Submit(_ context.Context, _ string, _ []clients.ClientSignature) (*clients.StatusResult, error) {
	f.submitCalls++

	return f.submit, nil
}

func (f *fakeSigner) Download(_ context.Context, _, _, sigFormat string) ([]byte, error) {
	f.downloadCalls++
	f.lastDownloadFormat = sigFormat

	return f.download, nil
}

func (f *fakeSigner) Validate(_ context.Context, _ []byte, filename string) ([]byte, error) {
	f.validateCalls++
	f.lastValidateFilename = filename

	if f.report == nil {
		return nil, errors.New("fake signer: no validation report scripted")
	}

	return f.report, nil
}

func (f *fakeSigner) Archive(_ context.Context, signed []byte, filename, authCert string) ([]byte, error) {
	f.lastArchiveFilename = filename
	f.lastArchiveAuthCert = authCert

	return append([]byte("archived:"), signed...), nil
}

// fakeDocs records calls and returns scripted results.
type fakeDocs struct {
	archived         *clients.ArchivedDoc
	storeArchivedErr error
	lastArchivedID   string
	meta             *clients.Meta
	dataObjects      []clients.DataObject
	container        *clients.Container
	signedDoc        *clients.SignedDoc
	content          []byte
	// metaErr / completeErr / storeSignedErr, when set, are returned from Metadata /
	// Complete / StoreSignedDocument. completeErrN bounds how many Complete calls fail
	// before succeeding (0 = always fail) — used to model a keep-latest CAS rejection
	// (chain_advanced) that clears on retry.
	metaErr        error
	completeErr    error
	completeErrN   int
	storeSignedErr error
	// head / headErr script CurrentHead (the server-authoritative chain-head lookup).
	// A nil head means "no signed head yet" → Begin signs the chain root.
	head    *clients.ChainHead
	headErr error

	metaCalls, dataObjectsCalls, completeCalls, storeSignedCalls, contentCalls, currentHeadCalls int
	lastMetaID, lastDataObjectsID, lastCompleteID, lastStoreSignedID, lastHeadRoot               string
	// lastOBO is the on-behalf-of identity of the most recent document call —
	// asserted to prove the user subject + token are threaded through.
	lastOBO clients.OnBehalf
}

func (f *fakeDocs) Metadata(_ context.Context, id string, obo clients.OnBehalf) (*clients.Meta, error) {
	f.metaCalls++
	f.lastMetaID = id
	f.lastOBO = obo

	if f.metaErr != nil {
		return nil, f.metaErr
	}

	return f.meta, nil
}

func (f *fakeDocs) DataObjects(_ context.Context, id string, obo clients.OnBehalf) ([]clients.DataObject, error) {
	f.dataObjectsCalls++
	f.lastDataObjectsID = id
	f.lastOBO = obo

	return f.dataObjects, nil
}

func (f *fakeDocs) Complete(_ context.Context, id string, _ []byte, obo clients.OnBehalf) (*clients.Container, error) {
	f.completeCalls++
	f.lastCompleteID = id
	f.lastOBO = obo

	if f.completeErr != nil && (f.completeErrN == 0 || f.completeCalls <= f.completeErrN) {
		return nil, f.completeErr
	}

	return f.container, nil
}

func (f *fakeDocs) StoreSignedDocument(_ context.Context, parentID string, _ []byte, _, _ string, obo clients.OnBehalf) (*clients.SignedDoc, error) {
	f.storeSignedCalls++
	f.lastStoreSignedID = parentID
	f.lastOBO = obo

	if f.storeSignedErr != nil {
		return nil, f.storeSignedErr
	}

	return f.signedDoc, nil
}

func (f *fakeDocs) StoreArchived(_ context.Context, id string, _ []byte, _ string, obo clients.OnBehalf) (*clients.ArchivedDoc, error) {
	f.lastArchivedID = id
	f.lastOBO = obo
	if f.storeArchivedErr != nil {
		return nil, f.storeArchivedErr
	}
	if f.archived != nil {
		return f.archived, nil
	}

	return &clients.ArchivedDoc{ID: id, ContentHash: "archived-hash"}, nil
}

func (f *fakeDocs) Content(_ context.Context, _ string, obo clients.OnBehalf) ([]byte, error) {
	f.contentCalls++
	f.lastOBO = obo

	return f.content, nil
}

func (f *fakeDocs) CurrentHead(_ context.Context, rootID string, obo clients.OnBehalf) (*clients.ChainHead, error) {
	f.currentHeadCalls++
	f.lastHeadRoot = rootID
	f.lastOBO = obo

	if f.headErr != nil {
		return nil, f.headErr
	}
	if f.head != nil {
		return f.head, nil
	}

	return &clients.ChainHead{}, nil // no signed head yet → Begin signs the chain root
}

// fakeEnvelope records slot-completion notifications and can be scripted to fail.
type fakeEnvelope struct {
	err error

	calls                                        int
	lastEnvelopeID, lastSlotID                   string
	lastSignatureID, lastSignedDocRef, lastJobID string

	// view is the envelope read returned from GetEnvelope (sign-target resolution);
	// getCalls records how many times it was read.
	view     *clients.EnvelopeView
	getCalls int
}

func (f *fakeEnvelope) GetEnvelope(_ context.Context, _ string, _ clients.OnBehalf) (*clients.EnvelopeView, error) {
	f.getCalls++
	if f.view != nil {
		return f.view, nil
	}

	return &clients.EnvelopeView{}, nil
}

func (f *fakeEnvelope) MarkSlotSigned(_ context.Context, envelopeID, slotID, signatureID, signedDocRef, jobID string) error {
	f.calls++
	f.lastEnvelopeID = envelopeID
	f.lastSlotID = slotID
	f.lastSignatureID = signatureID
	f.lastSignedDocRef = signedDocRef
	f.lastJobID = jobID

	return f.err
}

func newConductor(s *fakeSigner, d *fakeDocs) (*Conductor, store.Store) {
	st := store.NewMemory()

	// The default input carries a login method that permits its flow (the binding
	// gate fails closed on an absent or unknown method).
	return New(st, s, d, nil), st
}

func beginInput() BeginInput {
	return BeginInput{
		EnvelopeID:   "env-1",
		SlotID:       "slot-1",
		Flow:         "eparakstsMobile",
		SigFormat:    "XAdES",
		DocumentID:   "doc-1",
		CallerSub:    "user-1",
		SubjectToken: "tok-user-1",
		LoginMethod:  "eparakstsMobile",
		LoA:          "high",
	}
}

func TestBeginRemoteFlowSavesJobAndReturnsAuthorizeURL(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp.example/authorize?x=1")}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Filename: "contract.pdf", Mime: "application/pdf", ContentHash: "abc123"}}

	c, st := newConductor(signer, docs)

	res, err := c.Begin(context.Background(), beginInput())
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if res.JobID != "job-1" || res.State != "AWAITING_AUTHORIZATION" {
		t.Fatalf("unexpected result: %+v", res)
	}
	if res.AuthorizeURL != "https://idp.example/authorize?x=1" {
		t.Fatalf("authorize url not propagated: %q", res.AuthorizeURL)
	}
	// A redirect flow carries no client-side digests or signature algorithm.
	if len(res.Documents) != 0 || res.SignAlgorithm != "" {
		t.Fatalf("redirect flow should not surface digests: docs=%+v alg=%q", res.Documents, res.SignAlgorithm)
	}
	// A redirect flow sends no card certificates to prepare.
	if signer.lastSigningCert != "" || signer.lastAuthCert != "" {
		t.Fatalf("redirect flow must not send certs: signing=%q auth=%q", signer.lastSigningCert, signer.lastAuthCert)
	}
	// The digest fetched from the document service must be the one sent to prepare.
	if len(signer.lastPrepareDocs) != 1 || signer.lastPrepareDocs[0].DocumentHash != "abc123" {
		t.Fatalf("digest not forwarded to prepare: %+v", signer.lastPrepareDocs)
	}
	if signer.lastPrepareDocs[0].FileName != "contract.pdf" {
		t.Fatalf("filename not forwarded to prepare: %+v", signer.lastPrepareDocs[0])
	}
	// The document fetch must act on behalf of the signing user (subject + token
	// threaded through), so the user's own document is reachable.
	if docs.lastOBO.Sub != "user-1" || docs.lastOBO.Token != "tok-user-1" {
		t.Fatalf("document metadata not fetched on behalf of the user: %+v", docs.lastOBO)
	}
	// The mapping must be persisted before the redirect.
	job, err := st.GetJob(context.Background(), "job-1")
	if err != nil {
		t.Fatalf("job not saved: %v", err)
	}
	if job.CallerSub != "user-1" || job.SlotID != "slot-1" {
		t.Fatalf("job saved with wrong binding: %+v", job)
	}
}

// TestBeginWebEidThreadsCertsAndReturnsDigests proves the in-browser flow: the card
// certificates reach the provider's prepare, and the per-document digests + signature
// algorithm come back on the result for the client to sign on the card.
func TestBeginWebEidThreadsCertsAndReturnsDigests(t *testing.T) {
	signer := &fakeSigner{prepare: &clients.PrepareResult{
		JobID:         "job-1",
		Flow:          "webEid",
		State:         "AWAITING_CLIENT_SIGNATURE",
		SignAlgorithm: "RSA_SHA256",
		Documents:     []clients.DocRef{{DocumentID: "doc-1", Digest: "ZGlnZXN0", DigestAlgorithm: "SHA-256"}},
	}}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", ContentHash: "h"}}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.Flow = "webEid"
	in.LoginMethod = "webEid"
	in.SigningCertificate = "MIIsigningcert"
	in.AuthCertificate = "MIIauthcert"

	res, err := c.Begin(context.Background(), in)
	if err != nil {
		t.Fatalf("Begin: %v", err)
	}
	// The card certificates must reach the provider's prepare.
	if signer.lastSigningCert != "MIIsigningcert" || signer.lastAuthCert != "MIIauthcert" {
		t.Fatalf("certs not threaded to prepare: signing=%q auth=%q", signer.lastSigningCert, signer.lastAuthCert)
	}
	// The signature algorithm + per-document digests must be surfaced to sign.
	if res.SignAlgorithm != "RSA_SHA256" {
		t.Fatalf("signAlgorithm not surfaced: %q", res.SignAlgorithm)
	}
	if len(res.Documents) != 1 || res.Documents[0].DocumentID != "doc-1" || res.Documents[0].Digest != "ZGlnZXN0" {
		t.Fatalf("digests not surfaced: %+v", res.Documents)
	}
	// The in-browser flow has nowhere to redirect.
	if res.AuthorizeURL != "" {
		t.Fatalf("in-browser flow must not carry an authorize URL: %q", res.AuthorizeURL)
	}
}

// TestBeginContainerRegistersInnerDataObjects proves that signing a document which
// is itself an ASiC-E container registers its inner files for a parallel
// co-signature (the files array) rather than the container blob — so the document
// service can merge the result instead of nesting.
func TestBeginContainerRegistersInnerDataObjects(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{
		meta: &clients.Meta{ID: "doc-1", Kind: "container", Filename: "bundle.edoc", Mime: "application/vnd.etsi.asic-e+zip", ContentHash: "whole-blob-hash"},
		dataObjects: []clients.DataObject{
			{Name: "a.pdf", ContentHash: "hA", Algorithm: "SHA-256"},
			{Name: "b.txt", ContentHash: "hB", Algorithm: "SHA-256"},
		},
	}
	c, _ := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// A container source fetches its inner data objects on behalf of the user.
	if docs.dataObjectsCalls != 1 {
		t.Fatalf("container source must fetch inner data objects exactly once: calls=%d", docs.dataObjectsCalls)
	}
	if docs.lastOBO.Sub != "user-1" || docs.lastOBO.Token != "tok-user-1" {
		t.Fatalf("data objects not fetched on behalf of the user: %+v", docs.lastOBO)
	}

	if len(signer.lastPrepareDocs) != 1 {
		t.Fatalf("expected one prepare document: %+v", signer.lastPrepareDocs)
	}
	pd := signer.lastPrepareDocs[0]
	// The inner files are registered for a parallel co-signature — NOT the whole blob.
	if pd.DocumentHash != "" {
		t.Fatalf("container co-sign must not register the whole-blob hash: %q", pd.DocumentHash)
	}
	if len(pd.Files) != 2 ||
		pd.Files[0].Name != "a.pdf" || pd.Files[0].Digest != "hA" ||
		pd.Files[1].Name != "b.txt" || pd.Files[1].Digest != "hB" {
		t.Fatalf("inner files not registered for co-sign: %+v", pd.Files)
	}
}

// TestBeginPlainDocumentDoesNotFetchDataObjects proves a non-container source takes
// the single-digest path and never makes the co-sign data-objects call.
func TestBeginPlainDocumentDoesNotFetchDataObjects(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Kind: "source", Filename: "c.pdf", ContentHash: "abc123"}}
	c, _ := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if docs.dataObjectsCalls != 0 {
		t.Fatalf("a plain document must not fetch container data objects: calls=%d", docs.dataObjectsCalls)
	}
	if len(signer.lastPrepareDocs) != 1 || signer.lastPrepareDocs[0].DocumentHash != "abc123" || len(signer.lastPrepareDocs[0].Files) != 0 {
		t.Fatalf("plain document should register the single content hash: %+v", signer.lastPrepareDocs)
	}
}

// TestCoSignerSignsLatestContainerEndToEnd proves a co-signer signs the LATEST
// container in the envelope's chain (not the original document) and the merge
// completes — the reads/writes succeed directly via the standing chain ACL (granted
// at envelope send), with no per-call capability brokering.
func TestCoSignerSignsLatestContainerEndToEnd(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "cont-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		// The chain's current live head (server-resolved) is an ASiC-E container being
		// co-signed. The SPA's attached-document id (doc-1) is demoted to the chain root;
		// Begin signs the head the document store reports, not the client id.
		head:        &clients.ChainHead{ID: "cont-1", Kind: "container", ContentHash: "h"},
		meta:        &clients.Meta{ID: "cont-1", Kind: "container", Filename: "bundle.asice", ContentHash: "h"},
		dataObjects: []clients.DataObject{{Name: "a.pdf", ContentHash: "hA", Algorithm: "SHA-256"}},
		container:   &clients.Container{ContainerID: "cont-2", ContentHash: "h2"},
		content:     []byte("merged-container-bytes"),
	}
	env := &fakeEnvelope{
		view: &clients.EnvelopeView{
			Documents: []clients.EnvelopeDoc{{DocumentID: "doc-1"}},
			Slots: []clients.EnvelopeSlot{
				{Status: "signed", SignedDocRef: "cont-1", SignedAt: "2026-06-28T10:00:00Z"},
				{Status: "sent"},
			},
		},
	}
	c, _ := newConductor(signer, docs)
	c.WithEnvelope(env)

	in := beginInput()
	in.CallerSub = "cosigner-1"
	in.SubjectToken = "tok-cosigner"
	in.DocumentID = "doc-1" // the SPA sends the attached document; signflow targets the latest container

	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin (co-signer): %v", err)
	}

	// Begin signs the LATEST container, not the attached document.
	if len(signer.lastPrepareDocs) != 1 || signer.lastPrepareDocs[0].DocumentID != "cont-1" {
		t.Fatalf("did not target the latest container: %+v", signer.lastPrepareDocs)
	}
	if docs.lastDataObjectsID != "cont-1" {
		t.Fatalf("data objects read for the wrong document: %q", docs.lastDataObjectsID)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "cosigner-1", "tok-cosigner")
	if err != nil {
		t.Fatalf("Reconcile (co-signer finalize): %v", err)
	}
	if res.State != "COMPLETED" || res.ContainerID != "cont-2" {
		t.Fatalf("co-signer finalize did not complete the merge: %+v", res)
	}
	// The merge succeeds in a single write via the ACL (no broker, no retry).
	if docs.completeCalls != 1 {
		t.Fatalf("complete should succeed in one call via the ACL: calls=%d", docs.completeCalls)
	}
}

// TestBeginIgnoresStaleClientIdAndSignsServerHead is the regression for a co-signing
// defect where a stale client id lost a signature: Begin resolves the chain's CURRENT head
// server-side from the chain root (via CurrentHead) and signs THAT, ignoring the
// client's documentId. A co-signer whose SPA still holds the pre-co-sign id must sign
// the head the prior signer produced — never the stale id (which would 409 / lose a
// signature). The head is looked up by chain ROOT (from the envelope), not the client id.
func TestBeginIgnoresStaleClientIdAndSignsServerHead(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{
		// The chain's current live head, server-resolved from the root.
		head:        &clients.ChainHead{ID: "current-head", Kind: "container", ContentHash: "h"},
		meta:        &clients.Meta{ID: "current-head", Kind: "container", Filename: "b.asice", ContentHash: "h"},
		dataObjects: []clients.DataObject{{Name: "a.pdf", ContentHash: "hA", Algorithm: "SHA-256"}},
	}
	env := &fakeEnvelope{view: &clients.EnvelopeView{
		Documents: []clients.EnvelopeDoc{{DocumentID: "chain-root"}},
	}}
	c, _ := newConductor(signer, docs)
	c.WithEnvelope(env)

	in := beginInput()
	in.DocumentID = "STALE-client-id" // the SPA's stale id — must be ignored
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	// The head is resolved by chain ROOT (from the envelope), never the client id.
	if docs.lastHeadRoot != "chain-root" {
		t.Fatalf("head resolved by %q, want the chain root %q", docs.lastHeadRoot, "chain-root")
	}
	// Begin targets the server-resolved head, never the stale client id.
	if len(signer.lastPrepareDocs) != 1 || signer.lastPrepareDocs[0].DocumentID != "current-head" {
		t.Fatalf("Begin did not sign the server-resolved head (got %+v, stale id must be ignored)", signer.lastPrepareDocs)
	}
	if docs.lastMetaID != "current-head" {
		t.Fatalf("metadata read for %q, want the server-resolved head", docs.lastMetaID)
	}
}

// TestFinalizeRetriesOnChainAdvanced proves keep-latest concurrency handling: when a
// co-sign merge is rejected because the chain head advanced (409 chain_advanced),
// finalize re-submits the already-computed signature onto the new latest until it
// commits, bounded by maxCoSignRetries.
func TestFinalizeRetriesOnChainAdvanced(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "cont-1", DownloadURL: "/dl"}}},
		download: []byte("fileless"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:        &clients.Meta{ID: "cont-1", Kind: "container", Filename: "b.asice", ContentHash: "h"},
		dataObjects: []clients.DataObject{{Name: "a.pdf", ContentHash: "hA", Algorithm: "SHA-256"}},
		container:   &clients.Container{ContainerID: "cont-1", ContentHash: "h2"},
		content:     []byte("merged"),
		// The first two merge writes are rejected (chain advanced), then it commits.
		completeErr:  &clients.HTTPError{Service: "document", StatusCode: 409, Body: `{"error":"chain_advanced"}`},
		completeErrN: 2,
	}
	env := &fakeEnvelope{view: &clients.EnvelopeView{
		Documents: []clients.EnvelopeDoc{{DocumentID: "doc-1"}},
		Slots:     []clients.EnvelopeSlot{{Status: "signed", SignedDocRef: "cont-1", SignedAt: "2026-06-28T10:00:00Z"}, {Status: "sent"}},
	}}
	c, _ := newConductor(signer, docs)
	c.WithEnvelope(env)

	in := beginInput()
	in.CallerSub = "cosigner-1"
	in.SubjectToken = "tok"
	in.DocumentID = "doc-1"
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "cosigner-1", "tok")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "COMPLETED" {
		t.Fatalf("finalize did not complete after retries: %+v", res)
	}
	// Two rejections + the committing attempt = three Complete calls.
	if docs.completeCalls != 3 {
		t.Fatalf("expected 3 complete attempts (2 chain_advanced + 1 success), got %d", docs.completeCalls)
	}
}

// TestFinalizeChainAdvancedExhausted proves the bound: when every merge attempt
// loses the keep-latest CAS (the chain keeps advancing under the signer), finalize
// gives up after maxCoSignRetries and returns the structured ErrChainAdvanced — not
// an opaque upstream error — so the portal can ask the signer to review and re-sign.
func TestFinalizeChainAdvancedExhausted(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "cont-1", DownloadURL: "/dl"}}},
		download: []byte("fileless"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:        &clients.Meta{ID: "cont-1", Kind: "container", Filename: "b.asice", ContentHash: "h"},
		dataObjects: []clients.DataObject{{Name: "a.pdf", ContentHash: "hA", Algorithm: "SHA-256"}},
		container:   &clients.Container{ContainerID: "cont-1", ContentHash: "h2"},
		content:     []byte("merged"),
		// Every merge write is rejected (the chain head advances under us each time).
		completeErr:  &clients.HTTPError{Service: "document", StatusCode: 409, Body: `{"error":"chain_advanced"}`},
		completeErrN: 0, // 0 = always fail
	}
	env := &fakeEnvelope{view: &clients.EnvelopeView{
		Documents: []clients.EnvelopeDoc{{DocumentID: "doc-1"}},
		Slots:     []clients.EnvelopeSlot{{Status: "signed", SignedDocRef: "cont-1", SignedAt: "2026-06-28T10:00:00Z"}, {Status: "sent"}},
	}}
	c, _ := newConductor(signer, docs)
	c.WithEnvelope(env)

	in := beginInput()
	in.CallerSub = "cosigner-1"
	in.SubjectToken = "tok"
	in.DocumentID = "doc-1"
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	_, err := c.Reconcile(context.Background(), "job-1", 0, "cosigner-1", "tok")
	if !errors.Is(err, ErrChainAdvanced) {
		t.Fatalf("expected ErrChainAdvanced after exhausting retries, got %v", err)
	}
	// One initial attempt + maxCoSignRetries re-submits, then it gives up.
	if docs.completeCalls != 4 {
		t.Fatalf("expected 4 complete attempts (1 + 3 retries), got %d", docs.completeCalls)
	}
}

// TestBeginSurfacesNotFound proves a not-found document read surfaces as an error,
// not retried — the conductor no longer brokers a capability on a 404 (a co-signer's
// read is authorized up front by the standing chain ACL).
func TestBeginSurfacesNotFound(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "abc123"},
		metaErr: &clients.HTTPError{Service: "document", StatusCode: 404},
	}
	c, _ := newConductor(signer, docs)

	_, err := c.Begin(context.Background(), beginInput())
	if err == nil {
		t.Fatal("expected the not-found read to surface as an error")
	}
	if docs.metaCalls != 1 {
		t.Fatalf("metadata should not be retried: calls=%d", docs.metaCalls)
	}
}

func TestBeginRejectsUnsupportedFormat(t *testing.T) {
	signer := &fakeSigner{}
	docs := &fakeDocs{}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.SigFormat = "CAdES" // neither XAdES nor PAdES is wired

	_, err := c.Begin(context.Background(), in)
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Fatalf("expected ErrUnsupportedFormat, got %v", err)
	}
	if docs.metaCalls != 0 || signer.prepareCalls != 0 || signer.prepareFileCalls != 0 {
		t.Fatalf("collaborators called for an unsupported format")
	}
}

// PAdES has no hash-only mode, so Begin fetches the document bytes and sends them
// through the file-carrying prepare (a byte conduit), not the hash-only Prepare.
func TestBeginPAdESUsesByteConduit(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		content: []byte("%PDF-1.7 source"),
	}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.SigFormat = "PAdES"

	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin PAdES: %v", err)
	}
	if docs.contentCalls != 1 {
		t.Fatalf("expected the PDF bytes to be fetched once, got %d", docs.contentCalls)
	}
	if signer.prepareFileCalls != 1 || signer.prepareCalls != 0 {
		t.Fatalf("expected PrepareWithFile (byte conduit), got prepareFileCalls=%d prepareCalls=%d", signer.prepareFileCalls, signer.prepareCalls)
	}
	if len(signer.lastPrepareDocs) != 1 || signer.lastPrepareDocs[0].SignatureFormat != "PAdES" {
		t.Fatalf("expected one PAdES prepare doc, got %+v", signer.lastPrepareDocs)
	}
	ref := signer.lastPrepareDocs[0].FileRef
	if ref == "" || signer.lastPrepareFiles[ref] == nil {
		t.Fatalf("expected the PDF bytes under the doc's FileRef, docs=%+v files=%+v", signer.lastPrepareDocs, signer.lastPrepareFiles)
	}
	if signer.lastPrepareDocs[0].DocumentHash != "" {
		t.Fatalf("PAdES must not send a document hash (byte conduit)")
	}
}

// TestBeginDerivesFormatFromChainKindNotClientHint proves the chain's already-
// established form always wins over a stale/mismatched client hint: once a chain
// is a signed PDF or a container, every later signer's Begin call (any order, any
// session) is driven by what the chain actually is, not by what that signer's own
// client guessed — so a co-signer can never send a container's bytes down the PDF
// path, or a signed PDF's bytes down the hash-only container path.
func TestBeginDerivesFormatFromChainKindNotClientHint(t *testing.T) {
	t.Run("chain is already a signed PDF — a client hinting XAdES still gets PAdES", func(t *testing.T) {
		signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
		docs := &fakeDocs{
			meta:    &clients.Meta{ID: "pdf-1", Kind: "pdf", Filename: "c.pdf", Mime: "application/pdf", ContentHash: "h"},
			content: []byte("%PDF-1.7 already-signed"),
		}
		c, _ := newConductor(signer, docs)

		in := beginInput()
		in.SigFormat = "XAdES" // stale client hint — the chain moved on to PAdES

		if _, err := c.Begin(context.Background(), in); err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if signer.prepareFileCalls != 1 || signer.prepareCalls != 0 {
			t.Fatalf("expected the PAdES byte conduit despite the XAdES hint: prepareFileCalls=%d prepareCalls=%d", signer.prepareFileCalls, signer.prepareCalls)
		}
		if len(signer.lastPrepareDocs) != 1 || signer.lastPrepareDocs[0].SignatureFormat != "PAdES" {
			t.Fatalf("expected the prepare doc's format corrected to PAdES: %+v", signer.lastPrepareDocs)
		}
	})

	t.Run("chain is already a container — a client hinting PAdES still gets XAdES", func(t *testing.T) {
		signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
		docs := &fakeDocs{
			meta:        &clients.Meta{ID: "cont-1", Kind: "container", Filename: "bundle.asice", Mime: "application/vnd.etsi.asic-e+zip", ContentHash: "h"},
			dataObjects: []clients.DataObject{{Name: "a.pdf", ContentHash: "hA", Algorithm: "SHA-256"}},
		}
		c, _ := newConductor(signer, docs)

		in := beginInput()
		in.SigFormat = "PAdES" // stale client hint — the chain moved on to ASiC-E/XAdES

		if _, err := c.Begin(context.Background(), in); err != nil {
			t.Fatalf("Begin: %v", err)
		}
		if signer.prepareCalls != 1 || signer.prepareFileCalls != 0 {
			t.Fatalf("expected the hash-only container path despite the PAdES hint: prepareCalls=%d prepareFileCalls=%d", signer.prepareCalls, signer.prepareFileCalls)
		}
		if docs.contentCalls != 0 {
			t.Fatalf("a container co-sign must not fetch full bytes: contentCalls=%d", docs.contentCalls)
		}
		if len(signer.lastPrepareDocs) != 1 || signer.lastPrepareDocs[0].SignatureFormat != "XAdES" {
			t.Fatalf("expected the prepare doc's format corrected to XAdES: %+v", signer.lastPrepareDocs)
		}
	})
}

func TestReconcilePendingReturnsStateWithoutFinalizing(t *testing.T) {
	signer := &fakeSigner{
		prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:  &clients.StatusResult{JobID: "job-1", State: "SIGNING"},
	}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"}}
	c, _ := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "SIGNING" || res.ContainerID != "" {
		t.Fatalf("unexpected pending status: %+v", res)
	}
	if signer.downloadCalls != 0 || docs.completeCalls != 0 {
		t.Fatalf("finalized a job that was not ready")
	}
}

func TestReconcileReadyFinalizesValidatesAndIsIdempotent(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"},
		container: &clients.Container{ContainerID: "cont-1", ContentHash: "h2"},
		content:   []byte("full-container-bytes"),
	}
	c, st := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "COMPLETED" || res.ContainerID != "cont-1" {
		t.Fatalf("unexpected completed status: %+v", res)
	}
	if signer.downloadCalls != 1 || docs.completeCalls != 1 {
		t.Fatalf("finalize did not run exactly once: download=%d complete=%d", signer.downloadCalls, docs.completeCalls)
	}
	// The fileless container is completed against the document id, not the job id.
	if docs.lastCompleteID != "doc-1" {
		t.Fatalf("completed against wrong id: %q", docs.lastCompleteID)
	}

	// At-signing validation ran: the container was fetched and validated once, and
	// the normalized answer is carried on the status + recorded on the signature.
	if docs.contentCalls != 1 || signer.validateCalls != 1 {
		t.Fatalf("at-signing validation did not run once: content=%d validate=%d", docs.contentCalls, signer.validateCalls)
	}
	if res.Validation == nil || res.Validation.Verdict != "PASSED" || !res.Validation.Pass {
		t.Fatalf("validation answer not on completed status: %+v", res.Validation)
	}
	if res.SignatureID == "" {
		t.Fatalf("completed status carries no signature id")
	}
	sig, err := st.GetSignature(context.Background(), res.SignatureID)
	if err != nil {
		t.Fatalf("signature not recorded: %v", err)
	}
	if !sig.Validated || sig.ValidationID == "" || sig.Level != "QES" {
		t.Fatalf("validation not linked onto signature: %+v", sig)
	}

	// The job is now conductor-terminal.
	job, _ := st.GetJob(context.Background(), "job-1")
	if job.State != "COMPLETED" {
		t.Fatalf("job not marked completed: %q", job.State)
	}

	// A replayed poll must NOT re-drive the provider, re-assemble, or re-validate.
	statusBefore := signer.statusCalls
	res2, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("idempotent Reconcile: %v", err)
	}
	if res2.State != "COMPLETED" || res2.Validation != nil {
		t.Fatalf("replay should be a no-op without re-validation: %+v", res2)
	}
	if signer.statusCalls != statusBefore || signer.downloadCalls != 1 || docs.completeCalls != 1 || signer.validateCalls != 1 || docs.contentCalls != 1 {
		t.Fatalf("replay re-drove work: status=%d download=%d complete=%d validate=%d content=%d",
			signer.statusCalls, signer.downloadCalls, docs.completeCalls, signer.validateCalls, docs.contentCalls)
	}
}

// TestReconcileReadyCompletesEvenIfValidationFails proves at-signing validation is
// best-effort: a validation hiccup still completes the signing and records the
// signature (unvalidated), rather than losing it.
// A PAdES job finalizes through the signed-document store (the provider returns the
// complete signed PDF), not the container assembler.
func TestReconcileReadyFinalizesPAdESViaSignedStore(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("%PDF-1.7 signed"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		signedDoc: &clients.SignedDoc{SignedDocumentID: "signed-1", ContentHash: "h2"},
		content:   []byte("%PDF-1.7 source"),
	}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.SigFormat = "PAdES"
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "COMPLETED" || res.ContainerID != "signed-1" {
		t.Fatalf("PAdES did not finalize to the stored signed pdf: %+v", res)
	}
	if signer.lastDownloadFormat != "PAdES" {
		t.Fatalf("download did not request the PDF form: %q", signer.lastDownloadFormat)
	}
	if docs.storeSignedCalls != 1 || docs.completeCalls != 0 {
		t.Fatalf("PAdES must store the signed pdf, not complete a container: storeSigned=%d complete=%d", docs.storeSignedCalls, docs.completeCalls)
	}
	if docs.lastStoreSignedID != "doc-1" {
		t.Fatalf("signed pdf stored against the wrong parent id: %q", docs.lastStoreSignedID)
	}
	// The validation upload must carry a .pdf filename so the provider validates it
	// as a PDF, not as an ASiC-E container (a PDF isn't a ZIP → "cannot find central
	// directory"). This is the whole point of validationFilename by format.
	if signer.lastValidateFilename != "document.pdf" {
		t.Fatalf("PAdES validation used the wrong filename (must be a .pdf): %q", signer.lastValidateFilename)
	}
}

// A PAdES envelope co-sign takes a per-chain lock: while one slot is mid-signing, a
// concurrent slot on the same envelope is refused (a PAdES signature can't be merged,
// so signers serialize) rather than colliding at finalize.
func TestBeginPAdESEnvelopeLockRefusesConcurrentSigner(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		content: []byte("%PDF-1.7 base"),
	}
	c, _ := newConductor(signer, docs)

	in1 := beginInput()
	in1.SigFormat = "PAdES"
	in1.SlotID = "slot-1"
	if _, err := c.Begin(context.Background(), in1); err != nil {
		t.Fatalf("first Begin (slot-1): %v", err)
	}

	in2 := beginInput()
	in2.SigFormat = "PAdES"
	in2.SlotID = "slot-2"
	if _, err := c.Begin(context.Background(), in2); !errors.Is(err, ErrSigningInProgress) {
		t.Fatalf("concurrent Begin (slot-2): want ErrSigningInProgress, got %v", err)
	}
}

// A non-terminal Reconcile keeps the PAdES co-sign lock alive (keep-alive): a slow,
// still-in-flight signing must not let its lock lapse and admit a concurrent signer.
// Simulate a lapse (release the hold), then a pending Reconcile must re-assert it.
func TestReconcilePendingKeepsPAdESLockAlive(t *testing.T) {
	signer := &fakeSigner{
		prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:  &clients.StatusResult{JobID: "job-1", State: "SIGNING"},
	}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		content: []byte("%PDF-1.7 base"),
	}
	c, st := newConductor(signer, docs)

	in := beginInput()
	in.SigFormat = "PAdES"
	in.SlotID = "slot-1"
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin slot-1: %v", err)
	}

	// Simulate the lock lapsing mid-signing (a TTL expiry with nothing polling): drop it.
	if err := st.ReleaseChainLock(context.Background(), in.EnvelopeID, "slot-1"); err != nil {
		t.Fatalf("release: %v", err)
	}
	if locked, _, _ := st.ChainLockStatus(context.Background(), in.EnvelopeID); locked {
		t.Fatalf("precondition: lock should be free after release")
	}

	// A pending (non-terminal) Reconcile re-asserts slot-1's hold — keep-alive.
	if _, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1"); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	locked, holder, err := st.ChainLockStatus(context.Background(), in.EnvelopeID)
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	if !locked || holder != "slot-1" {
		t.Fatalf("keep-alive did not re-hold the lock: locked=%v holder=%q", locked, holder)
	}
}

// A non-terminal Reconcile relays the provider's device-push confirmation context
// (eID Scan): the verification code + signing deadline the provider publishes while
// waiting for the user to confirm on their phone, so the portal can show the code
// instead of a premature "finalizing" state.
func TestReconcilePendingRelaysVerificationCode(t *testing.T) {
	signer := &fakeSigner{
		prepare: mustPrepareWithURL("job-1", "eidScan", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status: &clients.StatusResult{
			JobID: "job-1", State: "SIGNING",
			VerificationCode: "4821", SigningDeadline: 1737467942694,
		},
	}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		content: []byte("%PDF-1.7 base"),
	}
	c, _ := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "SIGNING" || res.VerificationCode != "4821" || res.SigningDeadline != 1737467942694 {
		t.Fatalf("device-push context not relayed: state=%q code=%q deadline=%d", res.State, res.VerificationCode, res.SigningDeadline)
	}
}

// The chain lock frees when the holding sign finalizes, so the next signer can then
// begin (and signs the now-current PDF).
func TestBeginPAdESLockFreedAfterFinalize(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("%PDF-1.7 signed"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		signedDoc: &clients.SignedDoc{SignedDocumentID: "signed-1", ContentHash: "h2"},
		content:   []byte("%PDF-1.7 base"),
	}
	c, _ := newConductor(signer, docs)

	in1 := beginInput()
	in1.SigFormat = "PAdES"
	in1.SlotID = "slot-1"
	if _, err := c.Begin(context.Background(), in1); err != nil {
		t.Fatalf("Begin slot-1: %v", err)
	}
	// Finalizing slot-1's job frees the chain lock.
	if _, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1"); err != nil {
		t.Fatalf("Reconcile slot-1: %v", err)
	}

	// With the chain freed, slot-2 can now begin (a fresh job id).
	signer.prepare = mustPrepareWithURL("job-2", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")
	in2 := beginInput()
	in2.SigFormat = "PAdES"
	in2.SlotID = "slot-2"
	if _, err := c.Begin(context.Background(), in2); err != nil {
		t.Fatalf("Begin slot-2 after finalize should succeed (lock freed): %v", err)
	}
}

// Abandoning a signing attempt frees the chain lock (without declining), so a blocked
// co-signer can proceed — the signer cancelled at the provider and will retry.
func TestAbandonReleasesChainLock(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		content: []byte("%PDF-1.7 base"),
	}
	c, _ := newConductor(signer, docs)

	in1 := beginInput()
	in1.SigFormat = "PAdES"
	in1.SlotID = "slot-1"
	if _, err := c.Begin(context.Background(), in1); err != nil {
		t.Fatalf("Begin slot-1: %v", err)
	}

	in2 := beginInput()
	in2.SigFormat = "PAdES"
	in2.SlotID = "slot-2"
	if _, err := c.Begin(context.Background(), in2); !errors.Is(err, ErrSigningInProgress) {
		t.Fatalf("slot-2 before abandon: want ErrSigningInProgress, got %v", err)
	}

	// Slot-1 abandons its attempt (owner-checked) → lock frees.
	if err := c.Abandon(context.Background(), "job-1", "user-1"); err != nil {
		t.Fatalf("Abandon: %v", err)
	}

	signer.prepare = mustPrepareWithURL("job-2", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")
	if _, err := c.Begin(context.Background(), in2); err != nil {
		t.Fatalf("Begin slot-2 after abandon should succeed (lock freed): %v", err)
	}
}

// WaitChainFree reports free for an unlocked chain and not-free (within the window) for
// one a signer holds.
func TestWaitChainFree(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source", ContentHash: "h"},
		content: []byte("%PDF-1.7 base"),
	}
	c, _ := newConductor(signer, docs)

	// An untouched chain is free.
	if free, err := c.WaitChainFree(context.Background(), "env-1", 0); err != nil || !free {
		t.Fatalf("untouched chain: want free, got free=%v err=%v", free, err)
	}

	// After a slot begins, the chain is not free (wait=0 → a single check).
	in := beginInput()
	in.SigFormat = "PAdES"
	in.SlotID = "slot-1"
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if free, err := c.WaitChainFree(context.Background(), "env-1", 0); err != nil || free {
		t.Fatalf("locked chain: want not free, got free=%v err=%v", free, err)
	}
}

// A PAdES signed-store rejected as chain-advanced surfaces as ErrChainAdvanced with
// no retry — an embedded PDF signature can't be merged, so the signer re-signs.
func TestFinalizePAdESChainAdvancedSurfaces(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("%PDF-1.7 signed"),
	}
	docs := &fakeDocs{
		meta:           &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", Kind: "source"},
		content:        []byte("%PDF-1.7 source"),
		storeSignedErr: &clients.HTTPError{Service: "document", StatusCode: 409, Body: `{"error":"chain_advanced"}`},
	}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.SigFormat = "PAdES"
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	_, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if !errors.Is(err, ErrChainAdvanced) {
		t.Fatalf("expected ErrChainAdvanced, got %v", err)
	}
	if docs.storeSignedCalls != 1 {
		t.Fatalf("PAdES must not retry the store (no merge): storeSigned=%d", docs.storeSignedCalls)
	}
}

func TestReconcileReadyCompletesEvenIfValidationFails(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		// no report scripted → Validate errors
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"},
		container: &clients.Container{ContainerID: "cont-1"},
		content:   []byte("full-container-bytes"),
	}
	c, st := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "COMPLETED" || res.Validation != nil {
		t.Fatalf("expected completion without a validation answer: %+v", res)
	}
	sig, err := st.GetSignature(context.Background(), res.SignatureID)
	if err != nil {
		t.Fatalf("signature not recorded: %v", err)
	}
	if sig.Validated {
		t.Fatalf("signature should be recorded unvalidated when validation failed")
	}
}

// TestReconcileReadyNotifiesEnvelopeOnSlotCompletion proves that, when an envelope
// service is wired, finalize reports the slot's completion to it with the right
// envelope, slot, signature, signed-document ref, and job id.
func TestReconcileReadyNotifiesEnvelopeOnSlotCompletion(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"},
		container: &clients.Container{ContainerID: "cont-1", ContentHash: "h2"},
		content:   []byte("full-container-bytes"),
	}
	env := &fakeEnvelope{}
	c, _ := newConductor(signer, docs)
	c.WithEnvelope(env)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "COMPLETED" {
		t.Fatalf("expected completion: %+v", res)
	}

	if env.calls != 1 {
		t.Fatalf("envelope not notified exactly once: calls=%d", env.calls)
	}
	if env.lastEnvelopeID != "env-1" || env.lastSlotID != "slot-1" {
		t.Fatalf("notified for the wrong slot: envelope=%q slot=%q", env.lastEnvelopeID, env.lastSlotID)
	}
	if env.lastSignatureID != res.SignatureID || env.lastSignatureID == "" {
		t.Fatalf("notified with the wrong signature id: %q vs %q", env.lastSignatureID, res.SignatureID)
	}
	if env.lastSignedDocRef != "cont-1" {
		t.Fatalf("notified with the wrong signed-document ref: %q", env.lastSignedDocRef)
	}
	if env.lastJobID != "job-1" {
		t.Fatalf("notified with the wrong job id: %q", env.lastJobID)
	}
}

// TestReconcileReadyCompletesEvenIfEnvelopeNotifyFails proves the slot-completion
// notification is best-effort: a failing envelope callback must not fail the
// signing or roll back the recorded signature.
func TestReconcileReadyCompletesEvenIfEnvelopeNotifyFails(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"},
		container: &clients.Container{ContainerID: "cont-1", ContentHash: "h2"},
		content:   []byte("full-container-bytes"),
	}
	env := &fakeEnvelope{err: errors.New("envelope unreachable")}
	c, st := newConductor(signer, docs)
	c.WithEnvelope(env)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile must not fail when the envelope notification fails: %v", err)
	}
	if res.State != "COMPLETED" || res.SignatureID == "" {
		t.Fatalf("signing did not complete despite the failed notification: %+v", res)
	}
	// The notification was attempted (and retried) but did not roll back the signature.
	if env.calls == 0 {
		t.Fatalf("envelope notification was not attempted")
	}
	if _, err := st.GetSignature(context.Background(), res.SignatureID); err != nil {
		t.Fatalf("signature was lost after a failed notification: %v", err)
	}
}

// TestReconcileReadySkipsEnvelopeWhenUnconfigured proves the demo/single-document
// path is unaffected: with no envelope service wired, finalize completes without
// attempting any notification.
func TestReconcileReadySkipsEnvelopeWhenUnconfigured(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"},
		container: &clients.Container{ContainerID: "cont-1", ContentHash: "h2"},
		content:   []byte("full-container-bytes"),
	}
	c, _ := newConductor(signer, docs) // no WithEnvelope

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if res.State != "COMPLETED" {
		t.Fatalf("expected completion without an envelope service: %+v", res)
	}
}

// TestValidateOnDemand re-validates a recorded signature and links the answer.
func TestValidateOnDemand(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		// fail at-signing validation so the on-demand call is the one that links it
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"},
		container: &clients.Container{ContainerID: "cont-1"},
		content:   []byte("full-container-bytes"),
	}
	c, _ := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	// Now script a passing report and validate on demand.
	signer.report = []byte(passingReport)

	out, err := c.Validate(context.Background(), res.SignatureID, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if out.Result.Verdict != "PASSED" || !out.Result.Pass || out.Result.Signer != "TEST SIGNER" {
		t.Fatalf("unexpected validation result: %+v", out.Result)
	}
	if out.Signature.ID != res.SignatureID {
		t.Fatalf("validated the wrong signature: %q vs %q", out.Signature.ID, res.SignatureID)
	}
}

// TestValidateRejectsWrongOwner enforces ownership on re-validation.
func TestValidateRejectsWrongOwner(t *testing.T) {
	signer := &fakeSigner{
		prepare:  mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x"),
		status:   &clients.StatusResult{JobID: "job-1", State: "READY", Documents: []clients.DocRef{{DocumentID: "doc-1", DownloadURL: "/dl"}}},
		download: []byte("fileless-asice-bytes"),
		report:   []byte(passingReport),
	}
	docs := &fakeDocs{
		meta:      &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"},
		container: &clients.Container{ContainerID: "cont-1"},
		content:   []byte("full-container-bytes"),
	}
	c, _ := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	res, err := c.Reconcile(context.Background(), "job-1", 0, "user-1", "tok-user-1")
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if _, err := c.Validate(context.Background(), res.SignatureID, "someone-else", "tok-x"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
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

// passingReport is a verbatim provider validation report for one fully-valid
// qualified XAdES signature, in the provider's top-level {data:{…}} shape (the
// signing party nested under signerExt, RFC 3339 times).
var passingReport = `{"data":{"signatureForm":"ASiC-E","validationLevel":"ARCHIVAL_DATA",` +
	`"signaturesExt":[{"id":"S1","indication":"TOTAL-PASSED","subIndication":"",` +
	`"signatureLevel":"QESIG","signatureFormat":"XAdES_BASELINE_LT",` +
	`"signerExt":{"signedby":"TEST SIGNER","organization":null,` +
	`"signerSerialNumber":"` + testIDCodeLV(3) + `","registrationNumber":null},` +
	`"timeStamp":"2026-06-27T07:22:26Z","ocspResponceTime":"2026-06-27T07:22:27Z",` +
	`"maximumValidityTime":"2030-01-01T00:00:00Z","errors":[],"warnings":[]}],` +
	`"signaturesCount":1,"validSignaturesCount":1,` +
	`"validatedDocument":{"fileName":"contract.asice","includedFiles":["contract.pdf"]}}}`

func TestReconcileRejectsWrongOwner(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"}}
	c, _ := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	_, err := c.Reconcile(context.Background(), "job-1", 0, "someone-else", "tok-x")
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("expected ErrForbidden, got %v", err)
	}
}

func TestReconcileUnknownJobIsNotFound(t *testing.T) {
	c, _ := newConductor(&fakeSigner{}, &fakeDocs{})

	_, err := c.Reconcile(context.Background(), "missing", 0, "user-1", "tok-user-1")
	if !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestSubmitClientSignatureMirrorsState(t *testing.T) {
	signer := &fakeSigner{
		prepare: mustPrepareWithURL("job-1", "webEid", "AWAITING_CLIENT_SIGNATURE", ""),
		submit:  &clients.StatusResult{JobID: "job-1", State: "SIGNING"},
	}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"}}
	c, st := newConductor(signer, docs)

	in := beginInput()
	in.Flow = "webEid"
	in.LoginMethod = "webEid"
	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}

	res, err := c.SubmitClientSignature(context.Background(), "job-1",
		[]clients.ClientSignature{{DocumentID: "doc-1", SignatureValue: "sig"}}, "user-1")
	if err != nil {
		t.Fatalf("SubmitClientSignature: %v", err)
	}
	if res.State != "SIGNING" || signer.submitCalls != 1 {
		t.Fatalf("submit not mirrored: %+v calls=%d", res, signer.submitCalls)
	}
	job, _ := st.GetJob(context.Background(), "job-1")
	if job.State != "SIGNING" {
		t.Fatalf("state not reconciled in store: %q", job.State)
	}
}

// mustPrepareWithURL builds a PrepareResult by round-tripping JSON, so the
// unexported authorization field is populated through the public wire shape.
func mustPrepareWithURL(jobID, flow, state, authorizeURL string) *clients.PrepareResult {
	var p clients.PrepareResult
	body := `{"jobId":"` + jobID + `","flow":"` + flow + `","state":"` + state + `"`
	if authorizeURL != "" {
		body += `,"authorization":{"authorizeUrl":"` + authorizeURL + `"}`
	}
	body += `}`
	if err := json.Unmarshal([]byte(body), &p); err != nil {
		panic(err)
	}

	return &p
}
