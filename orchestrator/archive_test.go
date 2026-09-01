package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/signbyte/signflow/clients"
	"github.com/signbyte/signflow/store"
)

// ArchiveDocument is a straight conduit: fetch the signed head on the user's
// behalf, have the provider timestamp it, store it back in place — the result
// keeps the SAME document id and every leg carries the caller's identity.
func TestArchiveDocumentConduit(t *testing.T) {
	signer := &fakeSigner{}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "cont-1", Kind: "container", Filename: "contract.asice", Mime: "application/vnd.etsi.asic-e+zip"},
		content: []byte("signed container bytes"),
	}
	c := New(store.NewMemory(), signer, docs, nil)

	obo := clients.OnBehalf{Sub: "user-1", Token: "tok"}
	out, err := c.ArchiveDocument(context.Background(), "cont-1", "USERAUTHCERT", obo)
	if err != nil {
		t.Fatalf("archive: %v", err)
	}
	if out.ID != "cont-1" {
		t.Fatalf("archived id = %s, want the same head cont-1", out.ID)
	}
	if signer.lastArchiveFilename != "container.asice" {
		t.Fatalf("archive filename = %s, want container.asice", signer.lastArchiveFilename)
	}
	// The acting user's auth certificate must reach the provider — the
	// timestamp request is made in their name.
	if signer.lastArchiveAuthCert != "USERAUTHCERT" {
		t.Fatalf("archive auth cert = %q, want the caller's USERAUTHCERT", signer.lastArchiveAuthCert)
	}
	if docs.lastArchivedID != "cont-1" || docs.lastOBO.Sub != "user-1" {
		t.Fatalf("store-back = id %s obo %s, want cont-1 on behalf of user-1", docs.lastArchivedID, docs.lastOBO.Sub)
	}
}

// A signed PDF head archives down the PDF path (the provider picks its
// processing from the extension).
func TestArchiveDocumentPdfFilename(t *testing.T) {
	signer := &fakeSigner{}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "pdf-1", Kind: "pdf", Filename: "contract.pdf", Mime: "application/pdf"},
		content: []byte("signed pdf bytes"),
	}
	c := New(store.NewMemory(), signer, docs, nil)

	if _, err := c.ArchiveDocument(context.Background(), "pdf-1", "", clients.OnBehalf{Sub: "user-1"}); err != nil {
		t.Fatalf("archive: %v", err)
	}
	if signer.lastArchiveFilename != "document.pdf" {
		t.Fatalf("archive filename = %s, want document.pdf", signer.lastArchiveFilename)
	}
}

// ValidateDocument is validate-on-demand: bytes fetched on the user's behalf,
// the provider's report normalized and RETURNED — never persisted (the store
// stays untouched; the durable answer is the one recorded at signing time).
func TestValidateDocumentOnDemand(t *testing.T) {
	signer := &fakeSigner{report: []byte(`{"data":{"signatureForm":"PDF","validationLevel":"ARCHIVAL_DATA",` +
		`"signaturesExt":[{"id":"S1","indication":"TOTAL-PASSED","signatureLevel":"ADES_QC","signatureFormat":"PAdES_BASELINE_LT"}],` +
		`"signaturesCount":1,"validSignaturesCount":1}}`)}
	docs := &fakeDocs{
		meta:    &clients.Meta{ID: "pdf-1", Kind: "pdf", Filename: "signed.pdf", Mime: "application/pdf"},
		content: []byte("uploaded pre-signed pdf"),
	}
	st := store.NewMemory()
	c := New(st, signer, docs, nil)

	res, err := c.ValidateDocument(context.Background(), "pdf-1", clients.OnBehalf{Sub: "user-1", Token: "tok"})
	if err != nil {
		t.Fatalf("validate document: %v", err)
	}
	if !res.Pass || res.Verdict == "" {
		t.Fatalf("answer = pass %v verdict %q, want a passing verdict", res.Pass, res.Verdict)
	}
	if signer.lastValidateFilename != "document.pdf" {
		t.Fatalf("validate filename = %s, want document.pdf", signer.lastValidateFilename)
	}
	if res.ReportID != "" {
		t.Fatalf("on-demand validation persisted a report (%s) — it must not", res.ReportID)
	}
}

// A plain source has nothing to validate — rejected before any provider call.
func TestValidateDocumentRejectsSource(t *testing.T) {
	signer := &fakeSigner{}
	docs := &fakeDocs{meta: &clients.Meta{ID: "src-1", Kind: "source", Filename: "notes.txt"}}
	c := New(store.NewMemory(), signer, docs, nil)

	_, err := c.ValidateDocument(context.Background(), "src-1", clients.OnBehalf{Sub: "user-1"})
	if !errors.Is(err, ErrNothingToValidate) {
		t.Fatalf("err = %v, want ErrNothingToValidate", err)
	}
}

// A plain source carries no signature to extend — rejected before any provider
// call, with the sentinel the route maps to a 422.
func TestArchiveDocumentRejectsSource(t *testing.T) {
	signer := &fakeSigner{}
	docs := &fakeDocs{meta: &clients.Meta{ID: "src-1", Kind: "source", Filename: "notes.txt"}}
	c := New(store.NewMemory(), signer, docs, nil)

	_, err := c.ArchiveDocument(context.Background(), "src-1", "", clients.OnBehalf{Sub: "user-1"})
	if !errors.Is(err, ErrNotArchivable) {
		t.Fatalf("err = %v, want ErrNotArchivable", err)
	}
	if docs.contentCalls != 0 {
		t.Fatalf("content fetched %d times for a source, want 0", docs.contentCalls)
	}
}
