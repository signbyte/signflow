package clients

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Envelope is the client for the envelope/workflow service — the owner of the
// multi-slot envelope state machine. signflow notifies it when a slot's signing
// finalizes so the envelope can advance its own state. The notification goes out
// as signflow's own service identity (not on behalf of the signing user): it is a
// service-to-service state transition, not an owner-scoped read of the user's data.
type Envelope struct {
	doer     Doer
	baseURL  string
	audience string
}

// NewEnvelope builds an envelope-service client over the given outbound doer.
func NewEnvelope(d Doer, baseURL, audience string) *Envelope {
	return &Envelope{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

const (
	scopeEnvelopeTransition = "envelopes:transition"
	scopeEnvelopeRead       = "envelopes:read"
)

// slotSignedRequest is the body of the slot-completion notification.
type slotSignedRequest struct {
	SignatureID  string `json:"signatureId"`
	SignedDocRef string `json:"signedDocRef,omitempty"`
	JobID        string `json:"jobId"`
}

// MarkSlotSigned notifies the envelope service that a slot's signing has
// finalized, carrying the recorded signature id, the signed-document reference (if
// any), and the originating job id. The endpoint is idempotent, so a repeated call
// for the same slot is safe.
func (c *Envelope) MarkSlotSigned(ctx context.Context, envelopeID, slotID, signatureID, signedDocRef, jobID string) error {
	body, err := json.Marshal(slotSignedRequest{
		SignatureID:  signatureID,
		SignedDocRef: signedDocRef,
		JobID:        jobID,
	})
	if err != nil {
		return fmt.Errorf("envelope: marshal slot-signed: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/envelopes/%s/slots/%s/signed", c.baseURL, envelopeID, slotID)

	return doJSON(ctx, c.doer, "envelope", c.audience, scopeEnvelopeTransition, http.MethodPost, url, body, "application/json", nil)
}

// EnvelopeDoc is one attached document reference in the envelope read.
type EnvelopeDoc struct {
	DocumentID string `json:"documentId"`
}

// EnvelopeSlot is one slot in the envelope read: its status and the container it
// produced (if signed), with the signing time to order the co-sign chain.
type EnvelopeSlot struct {
	Status       string `json:"status"`
	SignedDocRef string `json:"signedDocRef"`
	SignedAt     string `json:"signedAt"`
}

// EnvelopeView is the slice of the envelope read signflow needs to resolve the
// signing target: the attached document(s) and the slots' produced containers.
type EnvelopeView struct {
	Documents []EnvelopeDoc  `json:"documents"`
	Slots     []EnvelopeSlot `json:"slots"`
}

// RootDocument returns the envelope's attached document (the chain root), or ""
// when none.
func (v *EnvelopeView) RootDocument() string {
	if len(v.Documents) == 0 {
		return ""
	}

	return v.Documents[0].DocumentID
}

// GetEnvelope reads the envelope on behalf of the signing user (the envelope grants
// an invited signer a participant read), so signflow can resolve the document to
// sign — the latest container in the chain, else the attached document.
func (c *Envelope) GetEnvelope(ctx context.Context, envelopeID string, obo OnBehalf) (*EnvelopeView, error) {
	url := fmt.Sprintf("%s/api/v1/envelopes/%s", c.baseURL, envelopeID)

	var out EnvelopeView
	if err := doJSONOnBehalf(ctx, c.doer, "envelope", c.audience, scopeEnvelopeRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}
