package routes

import (
	"errors"
	"strings"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/signflow/audit"
	"github.com/signbyte/signflow/clients"
	"github.com/signbyte/signflow/orchestrator"
	"github.com/signbyte/signflow/store"
)

// flowWebEid is the in-browser card flow: the client reads the card certificates,
// signflow returns the per-document digests, and the card signs them.
const flowWebEid = "webEid"

// createSigning — POST /api/v1/signings: begin signing a slot.
// {envelopeId, slotId, flow, sigFormat, documentId} → {jobId, state, authorizeUrl?}.
func (r *router) createSigning(ctx *azugo.Context) {
	if !r.requireScope(ctx, "create") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	var req createSigningRequest
	if err := ctx.Body.JSON(&req); err != nil { // auto-validates
		ctx.Error(err)

		return
	}

	// The in-browser flow needs the card certificates up front: the signing
	// certificate to compute the digest, the authentication certificate for
	// finalize. Reject early with a clear error rather than relaying an incomplete
	// request to the provider.
	if req.Flow == flowWebEid && (req.SigningCertificate == "" || req.AuthCertificate == "") {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("signingCertificate and authCertificate are required for the webEid flow")))

		return
	}

	// The binding claims the token carries: the login method gates which flow may
	// run, and is recorded with the flow as the binding evidence.
	loginMethod := ctx.User().ClaimValue("login_method")
	loa := ctx.User().ClaimValue("loa")

	res, err := c.Begin(ctx, orchestrator.BeginInput{
		EnvelopeID:         req.EnvelopeID,
		SlotID:             req.SlotID,
		Flow:               req.Flow,
		SigFormat:          req.SigFormat,
		DocumentID:         req.DocumentID,
		CallerSub:          ctx.User().ID(),
		SubjectToken:       subjectToken(ctx),
		LoginMethod:        loginMethod,
		LoA:                loa,
		SigningCertificate: req.SigningCertificate,
		AuthCertificate:    req.AuthCertificate,
		SignIdentityID:     req.SignIdentityID,
		SealID:             req.SealID,
		PostAuthRedirect:   req.PostAuthRedirect,
		AuthErrorRedirect:  req.AuthErrorRedirect,
	})
	if err != nil {
		// A binding rejection is itself evidence — record it before refusing.
		if errors.Is(err, orchestrator.ErrBindingMismatch) {
			r.Audit().AuthAssurance(ctx, audit.Assurance{
				CallerSub:      ctx.User().ID(),
				EnvelopeID:     req.EnvelopeID,
				Method:         loginMethod,
				LoA:            loa,
				BindingOutcome: "rejected",
			})
		}
		// Begin failures are otherwise invisible (the error is returned, not logged),
		// so a signing that cannot start leaves no trace. Log the cause for diagnosis.
		ctx.Log().Warn("signing begin failed: " + err.Error())
		r.mapErr(ctx, err)

		return
	}

	r.Audit().AuthAssurance(ctx, audit.Assurance{
		CallerSub:      ctx.User().ID(),
		EnvelopeID:     req.EnvelopeID,
		Method:         loginMethod,
		LoA:            loa,
		BindingOutcome: "bound",
	})

	// Surface the per-document digests for the in-browser flow; redirect flows carry
	// an authorize URL and no digests.
	var docs []digestRef
	for _, d := range res.Documents {
		docs = append(docs, digestRef{
			DocumentID:      d.DocumentID,
			Digest:          d.Digest,
			DigestAlgorithm: d.DigestAlgorithm,
		})
	}

	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&signingResponse{
		JobID:         res.JobID,
		State:         res.State,
		AuthorizeURL:  res.AuthorizeURL,
		SignAlgorithm: res.SignAlgorithm,
		Documents:     docs,
	})
}

// signingStatus — GET /api/v1/signings/{jobId}/status?wait=: reconciled status.
// On the first time the provider reports ready, the container is assembled and the
// signature recorded; thereafter the call is idempotent.
func (r *router) signingStatus(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	wait := 0
	if w, err := ctx.Query.IntOptional("wait"); err == nil && w != nil {
		wait = *w
	}

	res, err := c.Reconcile(ctx, ctx.Params.String("jobId"), wait, ctx.User().ID(), subjectToken(ctx))
	if err != nil {
		r.mapErr(ctx, err)

		return
	}

	// On the turn a signing first completes, the conductor validates the container;
	// record that lifecycle evidence. A replayed poll carries no validation, so this
	// emits once.
	if res.Validation != nil {
		r.Audit().ValidationPerformed(ctx, audit.Validation{
			CallerSub:  ctx.User().ID(),
			EnvelopeID: res.EnvelopeID,
			DocumentID: res.SlotID,
			Format:     res.Validation.Format,
			Passed:     res.Validation.Pass,
			ReportRef:  res.Validation.ReportID,
		})
	}

	ctx.JSON(&signingResponse{
		JobID:               res.JobID,
		State:               res.State,
		VerificationCode:    res.VerificationCode,
		VerificationMessage: res.VerificationMessage,
		SigningDeadline:     res.SigningDeadline,
		ContainerID:         res.ContainerID,
		SignatureID:         res.SignatureID,
	})
}

// maxChainFreeWait bounds the chain-free long-poll window (seconds) so a single call
// never holds a connection open indefinitely; the client re-calls to keep waiting.
const maxChainFreeWait = 10

// abandonSigning — POST /api/v1/signings/{jobId}/abandon: release the attempt's chain
// lock WITHOUT declining the slot (the signer cancelled at the provider or picked the
// wrong method and will retry). Owner-checked; the slot stays open for a fresh begin.
func (r *router) abandonSigning(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	if err := c.Abandon(ctx, ctx.Params.String("jobId"), ctx.User().ID()); err != nil {
		r.mapErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusNoContent)
}

// chainFree — GET /api/v1/chain-free?envelopeId=&wait=: a blocked co-signer's long-poll
// for when a PDF chain's active-signer lock frees (finalize / abandon / TTL). Holds open
// up to wait seconds (capped at maxChainFreeWait), then returns { free }.
func (r *router) chainFree(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	envelopeID, _ := ctx.Query.String("envelopeId")
	if envelopeID == "" {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("envelopeId is required")))

		return
	}

	wait := 0
	if w, err := ctx.Query.IntOptional("wait"); err == nil && w != nil {
		wait = *w
	}
	if wait > maxChainFreeWait {
		wait = maxChainFreeWait
	}

	free, err := c.WaitChainFree(ctx, envelopeID, wait)
	if err != nil {
		r.mapErr(ctx, err)

		return
	}

	ctx.JSON(&chainFreeResponse{Free: free})
}

// clientSignature — POST /api/v1/signings/{jobId}/client-signature: submit the
// in-browser client signature (eid flow).
func (r *router) clientSignature(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	var req clientSignatureRequest
	if err := ctx.Body.JSON(&req); err != nil { // auto-validates
		ctx.Error(err)

		return
	}

	sigs := make([]clients.ClientSignature, len(req.Signatures))
	for i, s := range req.Signatures {
		sigs[i] = clients.ClientSignature{DocumentID: s.DocumentID, SignatureValue: s.SignatureValue}
	}

	res, err := c.SubmitClientSignature(ctx, ctx.Params.String("jobId"), sigs, ctx.User().ID())
	if err != nil {
		r.mapErr(ctx, err)

		return
	}

	ctx.StatusCode(fasthttp.StatusAccepted)
	ctx.JSON(&signingResponse{JobID: res.JobID, State: res.State})
}

// validate — POST /api/v1/validations: validate / re-validate a recorded
// signature. Fetches the signed container, has the provider validate it,
// normalizes the verbatim report into the portal's field set, persists the
// normalized answer, records the lifecycle evidence, and returns the answer.
func (r *router) validate(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	var req validateRequest
	if err := ctx.Body.JSON(&req); err != nil { // auto-validates
		ctx.Error(err)

		return
	}

	out, err := c.Validate(ctx, req.SignatureID, ctx.User().ID(), subjectToken(ctx))
	if err != nil {
		r.mapErr(ctx, err)

		return
	}

	r.Audit().ValidationPerformed(ctx, audit.Validation{
		CallerSub:  ctx.User().ID(),
		EnvelopeID: out.Signature.EnvelopeID,
		DocumentID: out.Signature.SlotID,
		Format:     out.Result.Format,
		Passed:     out.Result.Pass,
		ReportRef:  out.Result.ReportID,
	})

	// The orchestrator's result IS the shared wire shape; only the caller
	// context (which recorded signature) is added here.
	res := *out.Result
	res.SignatureID = out.Signature.ID
	ctx.JSON(&res)
}

// validateDocument validates a signed document ON DEMAND — an uploaded
// already-signed file, or any signed head — and returns the normalized answer
// WITHOUT persisting anything: the durable answer stays the one recorded at
// signing time; this is repeatable evidence-on-request.
//
// @operationId ValidateDocument
// @title Validate a signed document on demand
// @param docValidateRequest body request.docValidateRequest true "The document id"
// @success 200 ValidationResult orchestrator.ValidationResult "The normalized validation answer"
// @failure 404 string string "Unknown document / caller not on its chain"
// @failure 422 string string "The document carries no signature to validate"
// @route /api/v1/document-validations [post].
func (r *router) validateDocument(ctx *azugo.Context) {
	if !r.requireScope(ctx, "read") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	var req docValidateRequest
	if err := ctx.Body.JSON(&req); err != nil { // auto-validates
		ctx.Error(err)

		return
	}

	res, err := c.ValidateDocument(ctx, req.DocumentID,
		clients.OnBehalf{Sub: ctx.User().ID(), Token: subjectToken(ctx)})
	if err != nil {
		r.mapErr(ctx, err)

		return
	}

	r.Audit().ValidationPerformed(ctx, audit.Validation{
		CallerSub:  ctx.User().ID(),
		DocumentID: req.DocumentID,
		Format:     res.Format,
		Passed:     res.Pass,
	})

	// The normalized result IS the shared wire shape; only the caller context
	// (which document was validated) is added here.
	out := *res
	out.DocumentID = req.DocumentID
	ctx.JSON(&out)
}

// conductor returns the signing conductor, or writes a 503 and returns nil when
// the collaborators it needs are not configured.
func (r *router) conductor(ctx *azugo.Context) *orchestrator.Conductor {
	c := r.Conductor()
	if c == nil {
		ctx.Error(pkerrors.NewProblem("err:signing:notConfigured",
			pkerrors.WithStatus(fasthttp.StatusServiceUnavailable),
			pkerrors.WithDetail("signing collaborators are not configured")))
	}

	return c
}

// requireScope enforces a signatures:<level> scope unless the dev-only user-token
// mode is on. Inbound callers (the Envelope/Workflow service + Portal-API) present
// service tokens; the matching grants are added with those callers.
func (r *router) requireScope(ctx *azugo.Context, level string) bool {
	if ctx.User().HasScopeLevel("signatures", level) {
		return true
	}

	ctx.Error(pkerrors.NewProblem("err:signing:forbidden",
		pkerrors.WithDetail("missing signatures:"+level+" scope")))

	return false
}

// mapErr maps a conductor/store error onto the right problem envelope.
// archiveTimestamp refreshes a signed document with a qualified archive
// timestamp (B-LT → B-LTA) on the user's behalf: fetch the signed head, have
// the provider embed an ARCHIVE_TIMESTAMP, store the archived form back in
// place. The response is the same document id pointing at the refreshed bytes.
//
// @operationId ArchiveTimestamp
// @title Add an archive timestamp to a signed document
// @param archiveRequest body request.archiveRequest true "The signed head document id"
// @success 200 archiveResponse archiveResponse "The refreshed head"
// @failure 404 string string "Unknown document / caller not on its chain"
// @failure 409 string string "Chain advanced (the head changed mid-archive)"
// @failure 422 string string "Not a signed document"
// @route /api/v1/archive-timestamps [post].
func (r *router) archiveTimestamp(ctx *azugo.Context) {
	if !r.requireScope(ctx, "write") {
		return
	}
	c := r.conductor(ctx)
	if c == nil {
		return
	}

	var req archiveRequest
	if err := ctx.Body.JSON(&req); err != nil { // auto-validates
		ctx.Error(err)

		return
	}

	out, err := c.ArchiveDocument(ctx, req.DocumentID, req.AuthCertificate,
		clients.OnBehalf{Sub: ctx.User().ID(), Token: subjectToken(ctx)})
	if err != nil {
		r.mapErr(ctx, err)

		return
	}

	ctx.JSON(&archiveResponse{
		DocumentID:  out.ID,
		ContentHash: out.ContentHash,
		Mime:        out.Mime,
		Size:        out.Size,
	})
}

func (r *router) mapErr(ctx *azugo.Context, err error) {
	switch {
	case errors.Is(err, store.ErrNotFound):
		ctx.Error(pkerrors.NewProblem("err:signing:notFound",
			pkerrors.WithDetail("unknown job")))
	case errors.Is(err, orchestrator.ErrNotArchivable):
		ctx.Error(pkerrors.NewProblem("err:signing:notArchivable",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("only a signed document can carry an archive timestamp")))
	case errors.Is(err, orchestrator.ErrNothingToValidate):
		ctx.Error(pkerrors.NewProblem("err:signing:nothingToValidate",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithDetail("the document carries no signature to validate")))
	case errors.Is(err, orchestrator.ErrForbidden):
		ctx.Error(pkerrors.NewProblem("err:signing:forbidden",
			pkerrors.WithDetail("caller does not own this job")))
	case errors.Is(err, orchestrator.ErrBindingMismatch):
		// A deliberately terse message: the caller must re-authenticate with the
		// method that matches the requested flow; signflow does not reveal more.
		ctx.Error(pkerrors.NewProblem("err:signing:bindingMismatch",
			pkerrors.WithStatus(fasthttp.StatusForbidden),
			pkerrors.WithDetail("login method does not permit this signing flow")))
	case errors.Is(err, orchestrator.ErrUnsupportedFormat):
		ctx.Error(pkerrors.NewProblem("err:signing:unsupportedFormat",
			pkerrors.WithStatus(fasthttp.StatusNotImplemented),
			pkerrors.WithDetail(err.Error())))
	case errors.Is(err, orchestrator.ErrSigningInProgress):
		// Another signer holds this PDF chain's active-signer lock. A structured 409 the
		// portal turns into "another party is signing — try again in a moment" guidance;
		// the caller retries once the chain frees and then signs the now-current PDF.
		ctx.Error(pkerrors.NewProblem("err:signing:inProgress",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithTitle("Another signer is signing this document"),
			pkerrors.WithDetail("another party is currently signing this document; try again in a moment")))
	case errors.Is(err, orchestrator.ErrChainAdvanced):
		// The document head moved on since this signing began, so the keep-latest CAS
		// refused the write. This covers two shapes and the wording must fit both: a
		// co-signer advanced the chain under the merge, OR the source is already signed
		// and a reload re-opened the wizard (single signer — no other party). A neutral,
		// actionable 409 the portal turns into "reload the latest and sign again"
		// guidance (same document domain code the store emits).
		ctx.Error(pkerrors.NewProblem("err:document:chainAdvanced",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithTitle("Document changed since signing began"),
			pkerrors.WithDetail("the document was updated since signing began; reload the latest version and sign again")))
	default:
		// A failed downstream call: relay the terminal problem (preserving its code,
		// source, and trace id) instead of collapsing it to a bare gateway error.
		var he *clients.HTTPError
		if errors.As(err, &he) {
			outer := he.StatusCode
			if outer >= fasthttp.StatusInternalServerError {
				outer = fasthttp.StatusBadGateway
			}
			down, _ := pkerrors.ParseProblem([]byte(he.Body))
			ctx.Error(pkerrors.Relay(down, r.AppName, outer))

			return
		}
		// No downstream response — an internal failure; log the cause off the wire.
		ctx.Log().Error("signing operation failed", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:signing:internal"))
	}
}

// subjectToken returns the raw inbound access token (without its auth scheme) so
// it can be exchanged for a delegated token on the document calls signflow makes
// for the user. Inbound tokens are DPoP-bound, so the scheme is "DPoP"; "Bearer"
// is tolerated.
func subjectToken(ctx *azugo.Context) string {
	h := ctx.Header.Get("Authorization")
	if i := strings.IndexByte(h, ' '); i >= 0 {
		return strings.TrimSpace(h[i+1:])
	}

	return strings.TrimSpace(h)
}
