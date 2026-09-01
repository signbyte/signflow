// Package orchestrator holds signflow's signing choreography: it turns a
// "sign this slot with this flow" request into a job on the signing provider,
// reconciles the provider's result, assembles the container through the document
// service, and records the applied signature. It stays byte-free for hash-only
// XAdES — only the document digest transits.
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/signbyte/signflow/clients"
	"github.com/signbyte/signflow/store"
)

// Errors the conductor returns; routes map these onto HTTP statuses.
var (
	// ErrUnsupportedFormat is returned for a signature format the conductor cannot
	// yet drive end-to-end (only hash-only XAdES is wired).
	ErrUnsupportedFormat = errors.New("orchestrator: unsupported signature format")
	// ErrForbidden is returned when the caller does not own the job.
	ErrForbidden = errors.New("orchestrator: caller does not own this job")
	// ErrNotArchivable is returned when an archive timestamp is requested for a
	// document that carries no signature to extend (a plain source).
	ErrNotArchivable = errors.New("orchestrator: only a signed document can carry an archive timestamp")
	// ErrNothingToValidate is returned when an on-demand validation is requested
	// for a document that carries no signature (a plain source).
	ErrNothingToValidate = errors.New("orchestrator: document carries no signature to validate")
	// ErrProviderState is returned when the provider reports a state the conductor
	// cannot act on.
	ErrProviderState = errors.New("orchestrator: unexpected provider state")
	// ErrChainAdvanced is returned when a co-sign merge keeps losing the keep-latest
	// CAS — the chain head advanced under it on every attempt within the retry bound.
	// The signing did not lose anything (the computed signature is independent); the
	// signer reviews the now-latest document and signs again.
	ErrChainAdvanced = errors.New("orchestrator: chain advanced under the co-sign merge")
	// ErrSigningInProgress is returned when another signer is already mid-signing this
	// PDF chain. A PAdES signature is embedded incrementally (it cannot be merged like
	// ASiC-E), so co-signers serialize: the caller retries once the current signer
	// finishes and then signs the now-current PDF.
	ErrSigningInProgress = errors.New("orchestrator: another signer is currently signing this document")
)

// signingLockTTLSeconds bounds how long a PAdES co-sign holds the chain's active-signer
// lock WITHOUT a refresh. It is a backstop against an abandoned/crashed signing wedging
// the chain, not the primary expiry: while a signing is in flight the lock is kept alive
// on each status reconcile (see Reconcile), and an explicit cancel frees it at once (see
// Abandon). The TTL is sized to cover the un-pollable window of a redirect flow — the
// user is away at the provider approving (e.g. an eID mobile app), so nothing is polling
// to refresh the lock — after which an unattended lock frees on its own. The document
// store's one-signed-PDF-per-chain constraint remains the correctness floor beneath it.
const signingLockTTLSeconds = 300

// chainFreePollInterval is how often WaitChainFree re-checks the lock while a blocked
// signer waits for the chain to free.
const chainFreePollInterval = time.Second

// Provider states the conductor reacts to.
const (
	stateReady  = "READY"
	stateFailed = "FAILED"
)

// A conductor-side terminal state stored on the job once the container is
// assembled and the signature recorded — distinct from the provider's own states,
// so a replayed poll is a no-op rather than a second assembly.
const stateCompleted = "COMPLETED"

// Signature formats the conductor drives. XAdES is hash-only + byte-free; PAdES
// embeds the signature in the PDF (no hash-only mode) so it transits the document
// bytes as a conduit.
const (
	formatXAdES = "XAdES"
	formatPAdES = "PAdES"
)

// SignerPort is the slice of the signing-provider client the conductor uses.
type SignerPort interface {
	Prepare(ctx context.Context, flow string, docs []clients.PrepareDoc, opts clients.PrepareOptions) (*clients.PrepareResult, error)
	// PrepareWithFile begins a byte-conduit job, sending the document bytes as
	// multipart file parts (used for PAdES, which has no hash-only mode).
	PrepareWithFile(ctx context.Context, flow string, docs []clients.PrepareDoc, files map[string][]byte, opts clients.PrepareOptions) (*clients.PrepareResult, error)
	Status(ctx context.Context, jobID string, wait int) (*clients.StatusResult, error)
	Submit(ctx context.Context, jobID string, sigs []clients.ClientSignature) (*clients.StatusResult, error)
	// Download fetches the signed document bytes; sigFormat selects the container
	// form (XAdES → a fileless ASiC-E, PAdES → the signed PDF as-is).
	Download(ctx context.Context, jobID, docID, sigFormat string) ([]byte, error)
	// Validate uploads a signed container and returns the provider's verbatim
	// validation report bytes.
	Validate(ctx context.Context, container []byte, filename string) ([]byte, error)
	// Archive uploads an already-signed document and returns its
	// archive-timestamped form (B-LT → B-LTA).
	Archive(ctx context.Context, signed []byte, filename, authCert string) ([]byte, error)
}

// DocumentPort is the slice of the document-service client the conductor uses.
// Every call acts on behalf of the signing user (the document is the user's,
// owner-filtered by the document service), so each carries the user's on-behalf
// identity.
type DocumentPort interface {
	Metadata(ctx context.Context, id string, obo clients.OnBehalf) (*clients.Meta, error)
	// DataObjects returns a container's inner data objects (name + digest) so a
	// parallel co-signature can be registered against the container's existing
	// files rather than the container blob. Called only for a container source.
	DataObjects(ctx context.Context, id string, obo clients.OnBehalf) ([]clients.DataObject, error)
	Complete(ctx context.Context, id string, fileless []byte, obo clients.OnBehalf) (*clients.Container, error)
	// StoreSignedDocument stores a finished, opaque signed document (a PAdES-signed
	// PDF) against its chain — no assembly; integrity is the embedded signature.
	StoreSignedDocument(ctx context.Context, parentID string, signed []byte, mime, filename string, obo clients.OnBehalf) (*clients.SignedDoc, error)
	// Content fetches a document's full bytes (the whole container must be sent for
	// validation — there is no hash-only validation path; also the PAdES byte conduit).
	Content(ctx context.Context, id string, obo clients.OnBehalf) ([]byte, error)
	// CurrentHead resolves a chain's current live signed head by chain root — the
	// server-authoritative artifact a co-signer signs on top of (never a stale client
	// id or a lagging envelope ref). An empty ID means no signed head yet (sign the root).
	CurrentHead(ctx context.Context, rootID string, obo clients.OnBehalf) (*clients.ChainHead, error)
	// StoreArchived replaces a signed head's bytes in place with its
	// archive-timestamped form — the same document, refreshed (CAS-guarded).
	StoreArchived(ctx context.Context, id string, archived []byte, filename string, obo clients.OnBehalf) (*clients.ArchivedDoc, error)
}

// EnvelopePort is the slice of the envelope-service client the conductor uses to
// report a slot's completion. The call goes out as signflow's own service identity
// (a service-to-service state transition, not an owner-scoped action), so it
// carries no on-behalf identity. Optional: nil when no envelope service is wired.
type EnvelopePort interface {
	MarkSlotSigned(ctx context.Context, envelopeID, slotID, signatureID, signedDocRef, jobID string) error
	// GetEnvelope reads the envelope on behalf of the signing user, so the conductor
	// can resolve the document to sign — the latest container in the co-sign chain,
	// else the attached document.
	GetEnvelope(ctx context.Context, envelopeID string, obo clients.OnBehalf) (*clients.EnvelopeView, error)
}

// Conductor drives the signing choreography over the store + collaborators.
type Conductor struct {
	store    store.Store
	signer   SignerPort
	docs     DocumentPort
	envelope EnvelopePort
	log      *zap.Logger
}

// New builds a Conductor. A nil logger is replaced with a no-op.
func New(st store.Store, signer SignerPort, docs DocumentPort, log *zap.Logger) *Conductor {
	if log == nil {
		log = zap.NewNop()
	}

	return &Conductor{store: st, signer: signer, docs: docs, log: log}
}

// WithEnvelope attaches the envelope-service notifier used to report a slot's
// completion after a signature is recorded. When unset, slot-completion
// notification is skipped (single-document/demo path with no envelope service).
func (c *Conductor) WithEnvelope(e EnvelopePort) *Conductor {
	c.envelope = e

	return c
}

// BeginInput starts a signing for one slot.
type BeginInput struct {
	EnvelopeID string
	SlotID     string
	Flow       string
	SigFormat  string
	// DocumentID is the document to sign. Until the Envelope/Workflow service can
	// resolve slot → document, the caller supplies it directly.
	DocumentID string
	CallerSub  string
	// SubjectToken is the caller's raw inbound token. signflow exchanges it for a
	// delegated token (token exchange) so the document fetch acts on behalf of the
	// signing user — the user's own document is otherwise invisible to signflow's
	// service identity.
	SubjectToken string
	// LoginMethod and LoA are the session's authentication binding, read from the
	// caller's token. The login method gates which signing flow may run and, with
	// the flow actually used, is recorded as the binding evidence on the durable
	// records. LoA is the level of assurance achieved at login.
	LoginMethod string
	LoA         string
	// SigningCertificate and AuthCertificate carry certificates for the signing
	// act: the card certificates for the in-browser flow (the signing
	// certificate lets the provider compute the digest the card signs, the
	// authentication certificate is used at finalize), or the caller's
	// login-captured identity certificates for a redirect flow. Both are public
	// certificates, request-scoped — never persisted or logged. Empty means the
	// provider resolves its own.
	SigningCertificate string
	AuthCertificate    string
	// SignIdentityID names the provider-side sign identity the certificates
	// belong to; with it and both certificates present the provider skips its
	// identity-resolution leg. SealID picks which seal signs (the e-seal flow
	// when the person holds several). Both optional pass-throughs.
	SignIdentityID string
	SealID         string
	// PostAuthRedirect and AuthErrorRedirect are the URLs the provider sends the
	// browser back to after a redirect flow's authorization completes or fails. They
	// carry a "{jobId}" placeholder the provider substitutes with the job id so the
	// portal recovers the job on return. Empty for the in-browser flow.
	PostAuthRedirect  string
	AuthErrorRedirect string
}

// DigestOut is a per-document digest the in-browser client must sign, surfaced from
// the provider's prepare response. Empty for the redirect flows.
type DigestOut struct {
	DocumentID      string
	Digest          string
	DigestAlgorithm string
}

// BeginResult is what the caller needs to continue: the job id, the current state,
// and either (for redirect flows) the URL the user must visit to authorize, or (for
// the in-browser flow) the signature algorithm and the per-document digests to sign.
type BeginResult struct {
	JobID         string
	State         string
	AuthorizeURL  string
	SignAlgorithm string
	Documents     []DigestOut
}

// Begin fetches the document digest, asks the provider to prepare the job,
// persists the slot↔job mapping before any redirect, and returns the job handle.
func (c *Conductor) Begin(ctx context.Context, in BeginInput) (*BeginResult, error) {
	if in.SigFormat != formatXAdES && in.SigFormat != formatPAdES {
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, in.SigFormat)
	}

	// Verify the session's login method permits the requested flow before any
	// provider work starts, so a signing under a mismatched binding can never begin.
	if err := checkBinding(in.LoginMethod, in.Flow); err != nil {
		return nil, err
	}

	obo := clients.OnBehalf{Sub: in.CallerSub, Token: in.SubjectToken}

	// Resolve the document to sign — SERVER-AUTHORITATIVE. For an envelope-backed slot,
	// take the chain ROOT from the envelope (authoritative for WHICH chain), then ask the
	// document store for that chain's CURRENT live head (authoritative for WHAT to sign).
	// So a co-signer who begins right after the prior signer finished signs the
	// just-produced head — for PAdES, on top of it — never a stale client id nor the
	// envelope's lagging signed_doc_ref (the root cause of the stale-head co-sign bug).
	// No signed head yet → sign the root (the first signature on the chain). A
	// single-document sign (no envelope) signs the supplied document directly.
	signDocID, rootDocID := in.DocumentID, in.DocumentID
	if c.envelope != nil && in.EnvelopeID != "" {
		if view, vErr := c.envelope.GetEnvelope(ctx, in.EnvelopeID, obo); vErr == nil {
			if root := view.RootDocument(); root != "" {
				rootDocID = root
			}
		}
		// Fail rather than guess: if the head can't be resolved we do not fall back to a
		// possibly-stale id (signing the wrong base would corrupt the co-signature). A
		// signed head → sign it; none yet → sign the root.
		head, hErr := c.docs.CurrentHead(ctx, rootDocID, obo)
		if hErr != nil {
			return nil, fmt.Errorf("orchestrator: resolve chain head: %w", hErr)
		}
		if head.ID != "" {
			signDocID = head.ID
		} else {
			signDocID = rootDocID
		}
	}

	// A co-signer's read succeeds via the standing chain ACL (granted at envelope
	// send) — no per-call capability brokering needed.
	meta, err := c.docs.Metadata(ctx, signDocID, obo)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: fetch document metadata: %w", err)
	}

	// The requested format only decides anything on a virgin source (the first
	// signature on the chain). Once a chain is already a container or a signed
	// PDF, its form is fixed — every later signer (any order, any session) must
	// follow it, never re-guess from their own client, so a stale/mismatched
	// client hint can never send a container's bytes down the PDF path or vice
	// versa.
	sigFormat := in.SigFormat
	switch meta.Kind {
	case "container":
		sigFormat = formatXAdES
	case "pdf":
		sigFormat = formatPAdES
	}

	// PAdES co-sign concurrency gate: a PDF signature is embedded incrementally and
	// cannot be merged, so only one signer may sign an envelope's chain at a time.
	// Whoever acquires the lock signs first; a concurrent signer is refused
	// (ErrSigningInProgress) and retries once the chain frees, then signs the now-current
	// PDF. XAdES is unaffected (its parallel signatures merge). The lock is released on a
	// completed sign (finalize) or by its TTL; the one-signed-PDF-per-chain constraint in
	// the document store is the correctness floor beneath this UX gate.
	locked := false
	if sigFormat == formatPAdES && in.EnvelopeID != "" {
		acquired, lErr := c.store.AcquireChainLock(ctx, in.EnvelopeID, in.SlotID, in.CallerSub, signingLockTTLSeconds)
		if lErr != nil {
			return nil, fmt.Errorf("orchestrator: acquire signing lock: %w", lErr)
		}
		if !acquired {
			return nil, ErrSigningInProgress
		}
		locked = true
		// Release on any failure before the job is durably persisted; a successful Begin
		// keeps the lock held (finalize releases it when the sign completes).
		defer func() {
			if locked {
				_ = c.store.ReleaseChainLock(ctx, in.EnvelopeID, in.SlotID)
			}
		}()
	}

	opts := clients.PrepareOptions{
		SigningCertificate: in.SigningCertificate,
		AuthCertificate:    in.AuthCertificate,
		SignIdentityID:     in.SignIdentityID,
		SealID:             in.SealID,
		PostAuthRedirect:   in.PostAuthRedirect,
		AuthErrorRedirect:  in.AuthErrorRedirect,
	}

	prepDoc := clients.PrepareDoc{
		DocumentID:      signDocID,
		FileName:        meta.Filename,
		MimeType:        meta.Mime,
		SignatureFormat: sigFormat,
	}

	var prep *clients.PrepareResult
	if sigFormat == formatPAdES {
		// PAdES embeds the signature in the PDF (no hash-only mode), so the whole
		// document transits the conductor to the provider as a transient byte conduit
		// (not retained). For a co-signature signDocID is the current signed PDF, so the
		// provider signs on top of the prior signatures (a sequential incremental sign).
		pdf, err := c.docs.Content(ctx, signDocID, obo)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: fetch document bytes: %w", err)
		}
		const fileRef = "file0"
		prepDoc.FileRef = fileRef
		prep, err = c.signer.PrepareWithFile(ctx, in.Flow, []clients.PrepareDoc{prepDoc}, map[string][]byte{fileRef: pdf}, opts)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: prepare: %w", err)
		}
	} else {
		if meta.Kind == "container" {
			// The document being signed is itself an ASiC-E container: register its inner
			// data objects so the signature is a parallel co-signature over the same
			// files (the document service then merges the result into the container),
			// rather than signing the container blob as one object (which would nest a
			// container inside a container).
			objs, err := c.docs.DataObjects(ctx, signDocID, obo)
			if err != nil {
				return nil, fmt.Errorf("orchestrator: fetch container data objects: %w", err)
			}
			for _, o := range objs {
				prepDoc.Files = append(prepDoc.Files, clients.PrepareFile{
					Name:            o.Name,
					Digest:          o.ContentHash,
					DigestAlgorithm: o.Algorithm,
				})
			}
		} else {
			prepDoc.DocumentHash = meta.ContentHash
			prepDoc.DigestAlgorithm = "SHA-256"
		}

		var err error
		prep, err = c.signer.Prepare(ctx, in.Flow, []clients.PrepareDoc{prepDoc}, opts)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: prepare: %w", err)
		}
	}

	// Persist the mapping BEFORE returning the redirect, so reconciliation survives
	// the user's round-trip even on another instance.
	if err := c.store.SaveJob(ctx, store.SaveJobInput{
		JobID:       prep.JobID,
		EnvelopeID:  in.EnvelopeID,
		SlotID:      in.SlotID,
		Flow:        in.Flow,
		SigFormat:   sigFormat,
		CallerSub:   in.CallerSub,
		State:       prep.State,
		LoginMethod: in.LoginMethod,
		LoA:         in.LoA,
	}); err != nil {
		return nil, fmt.Errorf("orchestrator: save job: %w", err)
	}

	// Surface the per-document digests for the in-browser flow (empty for redirect
	// flows, which carry an authorize URL instead).
	var digests []DigestOut
	for _, d := range prep.Documents {
		digests = append(digests, DigestOut{
			DocumentID:      d.DocumentID,
			Digest:          d.Digest,
			DigestAlgorithm: d.DigestAlgorithm,
		})
	}

	// The job is durably persisted; hand the lock off to the sign's lifecycle (finalize
	// or the TTL releases it) rather than the deferred failure release.
	locked = false

	return &BeginResult{
		JobID:         prep.JobID,
		State:         prep.State,
		AuthorizeURL:  prep.AuthorizeURL(),
		SignAlgorithm: prep.SignAlgorithm,
		Documents:     digests,
	}, nil
}

// maxCoSignRetries bounds how many times a co-sign merge is re-submitted after a
// keep-latest CAS rejection (chain_advanced) before giving up.
const maxCoSignRetries = 3

// isChainAdvanced reports whether err is a keep-latest CAS rejection (the chain
// head advanced since signing began — document-store returns 409). The signer
// re-submits the already-computed signature onto the new latest.
func isChainAdvanced(err error) bool {
	if err == nil {
		return false
	}

	var he *clients.HTTPError

	return errors.As(err, &he) && he.StatusCode == http.StatusConflict
}

// SigningStatus is the conductor's reconciled view of a job. On the turn the job
// first completes, ContainerID and the signature/envelope identity are set, and
// Validation carries the at-signing validation answer when validation succeeded
// (nil if it was deferred or could not be performed). On a replayed poll these are
// empty — the work ran once.
type SigningStatus struct {
	JobID               string
	State               string
	VerificationCode    string // device-push window (eID Scan): the code the user matches on their phone
	VerificationMessage string // device-push window (eID Scan): the prompt the device shows with the code
	SigningDeadline     int64  // device-push window (eID Scan): confirm-by deadline, epoch ms
	ContainerID         string // set on the turn the container is assembled
	SignatureID         string // set on completion
	EnvelopeID          string // set on completion (for the lifecycle audit event)
	SlotID              string // set on completion
	Validation          *ValidationResult
}

// ValidationOutcome pairs a signature record with its freshly-normalized validation
// answer — what the on-demand validate call returns.
type ValidationOutcome struct {
	Signature *store.Signature
	Result    *ValidationResult
}

// Reconcile polls the provider for the job's state (optionally long-polling), and
// on first success assembles the container and records the signature. It is
// idempotent: once the job reaches a conductor-terminal state a replayed call
// returns the stored state without re-driving the provider.
//
// Concurrent reconciles on the same job are serialized per slot in front of this
// call (a distributed lock); within a single instance the conductor-terminal
// state guards against a second assembly.
func (c *Conductor) Reconcile(ctx context.Context, jobID string, wait int, callerSub, subjectToken string) (*SigningStatus, error) {
	job, err := c.store.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if callerSub != "" && job.CallerSub != callerSub {
		return nil, ErrForbidden
	}
	if job.State == stateCompleted || job.State == stateFailed {
		return &SigningStatus{JobID: jobID, State: job.State}, nil
	}

	st, err := c.signer.Status(ctx, jobID, wait)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: provider status: %w", err)
	}
	if err := c.store.ReconcileJob(ctx, jobID, st.State); err != nil {
		return nil, fmt.Errorf("orchestrator: reconcile state: %w", err)
	}

	switch st.State {
	case stateReady:
		return c.finalize(ctx, job, st, subjectToken)
	case stateFailed:
		return &SigningStatus{JobID: jobID, State: stateFailed}, nil
	default:
		// Keep-alive: the signer is still in flight (redirect approval, PIN entry, …), so
		// re-assert the PAdES co-sign lock to refresh its TTL — a slow, human-paced signing
		// must not lapse its hold and let a concurrent signer slip onto the same chain.
		// Best-effort: if another slot has legitimately taken the chain over (this attempt
		// already lapsed), the same-slot re-acquire simply fails and this job loses at
		// finalize, exactly as before.
		if job.SigFormat == formatPAdES && job.EnvelopeID != "" {
			_, _ = c.store.AcquireChainLock(ctx, job.EnvelopeID, job.SlotID, job.CallerSub, signingLockTTLSeconds)
		}

		// Relay the device-push confirmation context (eID Scan): the provider
		// publishes the verification code, the device prompt, and the deadline
		// while it waits for the user to confirm on their phone, so the portal
		// can show the matching code + text instead of a premature "finalizing".
		return &SigningStatus{
			JobID:               jobID,
			State:               st.State,
			VerificationCode:    st.VerificationCode,
			VerificationMessage: st.VerificationMessage,
			SigningDeadline:     st.SigningDeadline,
		}, nil
	}
}

// finalize assembles the container for a ready job and records the signature.
// The document calls act on behalf of the job's owner (the signing user), using
// the caller's token from the current poll request.
func (c *Conductor) finalize(ctx context.Context, job *store.Job, st *clients.StatusResult, subjectToken string) (*SigningStatus, error) {
	docID := readyDocID(st)
	if docID == "" {
		return nil, fmt.Errorf("%w: ready job has no signed document", ErrProviderState)
	}

	obo := clients.OnBehalf{Sub: job.CallerSub, Token: subjectToken}

	// Fetch the signed artifact from the provider and hand it to the document service;
	// its stored id becomes the signature's signed_document_ref. The path differs by
	// format: XAdES fills a fileless container (byte-free, mergeable co-sign); PAdES
	// stores the complete signed PDF directly (embedded signature, not mergeable).
	var signedRef string
	if job.SigFormat == formatPAdES {
		signed, err := c.signer.Download(ctx, job.JobID, docID, formatPAdES)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: download signed pdf: %w", err)
		}

		// The signed PDF's filename mirrors the source's (a cosmetic download name).
		meta, err := c.docs.Metadata(ctx, docID, obo)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: fetch document metadata: %w", err)
		}

		out, err := c.docs.StoreSignedDocument(ctx, docID, signed, "application/pdf", meta.Filename, obo)
		if err != nil {
			// A concurrent sign advanced the chain head first. A PDF signature is
			// embedded and cannot be merged, so surface it so the signer re-signs the
			// now-current PDF (unlike the XAdES merge, there is no re-submit).
			if isChainAdvanced(err) {
				return nil, ErrChainAdvanced
			}

			return nil, fmt.Errorf("orchestrator: store signed pdf: %w", err)
		}
		signedRef = out.SignedDocumentID
	} else {
		fileless, err := c.signer.Download(ctx, job.JobID, docID, formatXAdES)
		if err != nil {
			return nil, fmt.Errorf("orchestrator: download container: %w", err)
		}

		// The co-signer's merge write goes through the standing chain ACL. keep-latest
		// replaces the one container per chain under an optimistic CAS: if a concurrent
		// co-sign advanced the chain head first, the merge is rejected (chain_advanced);
		// re-submit the already-computed signature onto the new latest (parallel
		// signatures are independent — no re-signing), bounded by a few attempts.
		var container *clients.Container
		for attempt := 0; ; attempt++ {
			container, err = c.docs.Complete(ctx, docID, fileless, obo)
			if !isChainAdvanced(err) || attempt >= maxCoSignRetries {
				break
			}
		}
		if err != nil {
			// Exhausting the retries on a CAS rejection is a distinct, recoverable
			// outcome: the chain kept advancing under us. Surface it as such so the
			// caller can tell the signer to review the now-latest and sign again, rather
			// than as an opaque upstream failure.
			if isChainAdvanced(err) {
				return nil, ErrChainAdvanced
			}

			return nil, fmt.Errorf("orchestrator: complete container: %w", err)
		}
		signedRef = container.ContainerID
	}

	// Record the applied signature (initially unvalidated); the at-signing
	// validation answer is linked back by the validation step below.
	sigID, err := c.store.InsertSignature(ctx, store.SignatureInput{
		JobID:             job.JobID,
		EnvelopeID:        job.EnvelopeID,
		SlotID:            job.SlotID,
		FlowUsed:          job.Flow,
		SigFormat:         job.SigFormat,
		SignedDocumentRef: signedRef,
		Validated:         false,
		LoginMethod:       job.LoginMethod,
		LoA:               job.LoA,
	})
	if err != nil {
		return nil, fmt.Errorf("orchestrator: record signature: %w", err)
	}

	status := &SigningStatus{
		JobID:       job.JobID,
		State:       stateCompleted,
		ContainerID: signedRef,
		SignatureID: sigID,
		EnvelopeID:  job.EnvelopeID,
		SlotID:      job.SlotID,
	}

	// Mark the job conductor-terminal BEFORE validating, so a crash during the
	// best-effort validation can't make a replayed poll re-finalize (which would
	// record a second signature). The signature is already persisted either way.
	if err := c.store.ReconcileJob(ctx, job.JobID, stateCompleted); err != nil {
		return nil, fmt.Errorf("orchestrator: mark completed: %w", err)
	}

	// The sign is durably terminal — free the PAdES co-sign lock so the next signer can
	// proceed at once rather than waiting out the TTL. No-op for XAdES / non-envelope.
	if job.SigFormat == formatPAdES && job.EnvelopeID != "" {
		_ = c.store.ReleaseChainLock(ctx, job.EnvelopeID, job.SlotID)
	}

	// Notify the envelope service that the slot's signing finalized, so it can
	// advance its state machine. Best-effort: the signature is already durable and
	// the notification is reconcilable, so a failure must not lose or roll back the
	// signing — log and continue. Skipped when no envelope service is wired.
	c.notifySlotSigned(ctx, job, sigID, signedRef)

	// Validate the assembled container at signing time and record the answer on the
	// signature. This is best-effort: a validation hiccup must not lose the signature
	// we just applied — the record stays unvalidated and can be re-validated later.
	if res, vErr := c.runValidation(ctx, sigID, signedRef, job.SigFormat, job.EnvelopeID, job.SlotID, obo); vErr != nil {
		c.log.Warn("at-signing validation did not complete; signature recorded unvalidated",
			zap.String("job_id", job.JobID),
			zap.String("signature_id", sigID),
			zap.Error(vErr))
	} else {
		status.Validation = res
	}

	c.log.Info("signing completed",
		zap.String("job_id", job.JobID),
		zap.String("envelope_id", job.EnvelopeID),
		zap.String("slot_id", job.SlotID),
		zap.String("container_id", signedRef))

	return status, nil
}

// notifySlotSignedAttempts bounds the slot-completion notification retries. The
// envelope endpoint is idempotent, so a retry is safe; this stays small so the
// request path is never held up by the notification.
const notifySlotSignedAttempts = 2

// notifySlotSigned reports the slot's completion to the envelope service so it can
// advance its state machine. It is best-effort and non-blocking on the signing
// outcome: a failure is logged and swallowed (the signature is already durable and
// the notification is reconcilable). It is a no-op when no envelope service is
// wired.
func (c *Conductor) notifySlotSigned(ctx context.Context, job *store.Job, signatureID, signedDocRef string) {
	if c.envelope == nil {
		return
	}

	var err error
	for attempt := 1; attempt <= notifySlotSignedAttempts; attempt++ {
		if err = c.envelope.MarkSlotSigned(ctx, job.EnvelopeID, job.SlotID, signatureID, signedDocRef, job.JobID); err == nil {
			return
		}
	}

	c.log.Warn("could not notify the envelope service of slot completion; the signature is recorded and the notification is reconcilable",
		zap.String("job_id", job.JobID),
		zap.String("envelope_id", job.EnvelopeID),
		zap.String("slot_id", job.SlotID),
		zap.String("signature_id", signatureID),
		zap.Error(err))
}

// Validate re-runs validation on an already-recorded signature on demand: it
// resolves the signature, checks the caller owns it, fetches the signed container,
// asks the provider to validate it, normalizes the answer, persists it, and links
// it onto the signature record.
func (c *Conductor) Validate(ctx context.Context, signatureID, callerSub, subjectToken string) (*ValidationOutcome, error) {
	sig, err := c.store.GetSignature(ctx, signatureID)
	if err != nil {
		return nil, err
	}

	// Ownership + the on-behalf-of subject both live on the signing job (the
	// signature record carries no caller).
	job, err := c.store.GetJob(ctx, sig.JobID)
	if err != nil {
		return nil, err
	}
	if callerSub != "" && job.CallerSub != callerSub {
		return nil, ErrForbidden
	}

	if sig.SignedDocumentRef == "" {
		return nil, fmt.Errorf("%w: signature has no signed document to validate", ErrProviderState)
	}

	res, err := c.runValidation(ctx, signatureID, sig.SignedDocumentRef, job.SigFormat, job.EnvelopeID, job.SlotID, clients.OnBehalf{Sub: job.CallerSub, Token: subjectToken})
	if err != nil {
		return nil, err
	}

	return &ValidationOutcome{Signature: sig, Result: res}, nil
}

// ArchiveDocument refreshes a signed document with a qualified archive timestamp
// (B-LT → B-LTA): fetch the signed head's bytes on the user's behalf (the chain
// ACL authorizes the read), have the provider embed an ARCHIVE_TIMESTAMP in each
// signature, and store the archived form back IN PLACE as the same document. No
// job or signature record is involved — this refreshes an existing artifact; a
// concurrent co-sign wins the CAS swap and the caller retries on the new head.
func (c *Conductor) ArchiveDocument(ctx context.Context, documentID, authCert string, obo clients.OnBehalf) (*clients.ArchivedDoc, error) {
	meta, err := c.docs.Metadata(ctx, documentID, obo)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: fetch document metadata: %w", err)
	}
	if meta.Kind == "source" {
		return nil, ErrNotArchivable
	}

	content, err := c.docs.Content(ctx, documentID, obo)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: fetch document content: %w", err)
	}

	archived, err := c.signer.Archive(ctx, content, providerFilename(meta), authCert)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: archive document: %w", err)
	}

	out, err := c.docs.StoreArchived(ctx, documentID, archived, meta.Filename, obo)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: store archived document: %w", err)
	}

	return out, nil
}

// ValidateDocument validates a signed document ON DEMAND — an uploaded
// already-signed file, or any signed head — without touching the signing
// records: fetch the bytes on the user's behalf (the chain ACL authorizes),
// have the provider validate them, normalize the verbatim report, and RETURN
// the answer. Nothing is persisted: the durable answer stays the one recorded
// at signing time; an on-demand check is repeatable evidence-on-request.
func (c *Conductor) ValidateDocument(ctx context.Context, documentID string, obo clients.OnBehalf) (*ValidationResult, error) {
	meta, err := c.docs.Metadata(ctx, documentID, obo)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: fetch document metadata: %w", err)
	}
	if meta.Kind == "source" {
		return nil, ErrNothingToValidate
	}

	content, err := c.docs.Content(ctx, documentID, obo)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: fetch document content: %w", err)
	}

	report, err := c.signer.Validate(ctx, content, providerFilename(meta))
	if err != nil {
		return nil, fmt.Errorf("orchestrator: validate document: %w", err)
	}

	return normalizeReport(report)
}

// providerFilename gives the provider the file extension it uses to pick its
// processing path: a signed PDF stays a PDF, everything else is an ASiC-E
// container (mirrors validationFilename, keyed on the document rather than a
// job's signature format).
func providerFilename(m *clients.Meta) string {
	if m.Kind == "pdf" || strings.Contains(m.Mime, "pdf") {
		return "document.pdf"
	}

	return "container.asice"
}

// Abandon releases a signing attempt's hold on its chain WITHOUT declining the slot:
// the signer cancelled at the provider or picked the wrong method and wants to retry,
// so the slot stays open for a fresh Begin while the PAdES co-sign lock frees at once —
// another party isn't left waiting on an attempt that is no longer live. Owner-checked;
// the release is no-op-safe (nothing held → nothing freed; XAdES has no lock).
func (c *Conductor) Abandon(ctx context.Context, jobID, callerSub string) error {
	job, err := c.store.GetJob(ctx, jobID)
	if err != nil {
		return err
	}
	if callerSub != "" && job.CallerSub != callerSub {
		return ErrForbidden
	}
	if job.SigFormat == formatPAdES && job.EnvelopeID != "" {
		_ = c.store.ReleaseChainLock(ctx, job.EnvelopeID, job.SlotID)
	}

	return nil
}

// WaitChainFree blocks until the envelope's chain has no active-signer lock — a blocked
// co-signer's "wait until the current signer finishes" long-poll — or waitSeconds
// elapses. Returns whether the chain is free. The caller re-calls to keep waiting past
// one window. The chain frees on finalize, abandon, or the lock's TTL.
func (c *Conductor) WaitChainFree(ctx context.Context, envelopeID string, waitSeconds int) (bool, error) {
	deadline := time.Now().Add(time.Duration(waitSeconds) * time.Second)
	for {
		locked, _, err := c.store.ChainLockStatus(ctx, envelopeID)
		if err != nil {
			return false, err
		}
		if !locked {
			return true, nil
		}
		if !time.Now().Before(deadline) {
			return false, nil
		}
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-time.After(chainFreePollInterval):
		}
	}
}

// validationFilename gives the provider the file extension it uses to pick the
// validator: a PAdES artifact is a signed PDF, everything else is an ASiC-E
// container. Without a recognisable extension the provider defaults to container
// (ZIP) processing, which fails on a PDF ("cannot find central directory").
func validationFilename(sigFormat string) string {
	if sigFormat == formatPAdES {
		return "document.pdf"
	}
	return "container.asice"
}

// runValidation fetches the signed container, has the provider validate it,
// normalizes the verbatim report into the portal's answer, persists the normalized
// result, and links it onto the signature record. The verbatim report is never
// stored — only the normalized answer is the evidence.
func (c *Conductor) runValidation(ctx context.Context, signatureID, containerID, sigFormat, envelopeID, slotID string, obo clients.OnBehalf) (*ValidationResult, error) {
	// The co-signer's container read goes through the standing chain ACL.
	content, err := c.docs.Content(ctx, containerID, obo)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: fetch container content: %w", err)
	}

	report, err := c.signer.Validate(ctx, content, validationFilename(sigFormat))
	if err != nil {
		return nil, fmt.Errorf("orchestrator: validate container: %w", err)
	}

	res, err := normalizeReport(report)
	if err != nil {
		return nil, err
	}

	reportID, err := c.store.StoreReport(ctx, store.ReportInput{
		SignatureID:     signatureID,
		Verdict:         res.Verdict,
		Format:          res.Format,
		Level:           res.Level,
		Signer:          res.Signer,
		SignerSerial:    res.SignerSerial,
		Organization:    res.Organization,
		ContainerForm:   res.ContainerForm,
		SigningTime:     res.SigningTime,
		RevocationTime:  res.RevocationTime,
		MaxValidityTime: res.MaxValidityTime,
		SignedFiles:     res.SignedFiles,
		Warnings:        res.Warnings,
		Errors:          res.Errors,
	})
	if err != nil {
		return nil, fmt.Errorf("orchestrator: persist validation result: %w", err)
	}
	res.ReportID = reportID

	if err := c.store.RecordValidation(ctx, signatureID, reportID, res.Pass, res.Level); err != nil {
		return nil, fmt.Errorf("orchestrator: link validation result: %w", err)
	}

	return res, nil
}

// SubmitClientSignature hands a client-produced signature (the in-browser flow) to
// the provider and mirrors the resulting state. A subsequent status poll drives the
// job to completion.
func (c *Conductor) SubmitClientSignature(ctx context.Context, jobID string, sigs []clients.ClientSignature, callerSub string) (*SigningStatus, error) {
	job, err := c.store.GetJob(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if callerSub != "" && job.CallerSub != callerSub {
		return nil, ErrForbidden
	}

	st, err := c.signer.Submit(ctx, jobID, sigs)
	if err != nil {
		return nil, fmt.Errorf("orchestrator: submit client signature: %w", err)
	}
	if err := c.store.ReconcileJob(ctx, jobID, st.State); err != nil {
		return nil, fmt.Errorf("orchestrator: reconcile state: %w", err)
	}

	return &SigningStatus{JobID: jobID, State: st.State}, nil
}

// readyDocID returns the id of the first ready document (the one carrying a
// download URL), falling back to the first document when none is marked.
func readyDocID(st *clients.StatusResult) string {
	for _, d := range st.Documents {
		if d.DownloadURL != "" {
			return d.DocumentID
		}
	}
	if len(st.Documents) > 0 {
		return st.Documents[0].DocumentID
	}

	return ""
}
