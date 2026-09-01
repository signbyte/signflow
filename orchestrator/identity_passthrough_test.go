package orchestrator

import (
	"context"
	"testing"

	"github.com/signbyte/signflow/clients"
)

// TestBeginThreadsIdentityPassThrough proves the caller-supplied sign identity,
// certificates and seal pick reach the provider's prepare unchanged — the
// contract that lets a login-captured identity skip the provider's own
// identity-resolution leg.
func TestBeginThreadsIdentityPassThrough(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://provider/authorize2")}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Filename: "c.pdf", Mime: "application/pdf", ContentHash: "h"}}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.Flow = "eparakstsMobile"
	in.LoginMethod = "eparakstsMobile"
	in.SignIdentityID = "id-serverid-sign"
	in.SigningCertificate = "MIIsignCaptured"
	in.AuthCertificate = "MIIauthCaptured"
	in.SealID = "id-seal-2"

	if _, err := c.Begin(context.Background(), in); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if signer.lastSignIdentityID != "id-serverid-sign" || signer.lastSealID != "id-seal-2" {
		t.Fatalf("identity pass-through not threaded: signIdentityId=%q sealId=%q",
			signer.lastSignIdentityID, signer.lastSealID)
	}
	if signer.lastSigningCert != "MIIsignCaptured" || signer.lastAuthCert != "MIIauthCaptured" {
		t.Fatalf("captured certs not threaded: signing=%q auth=%q",
			signer.lastSigningCert, signer.lastAuthCert)
	}
}
