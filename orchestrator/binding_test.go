package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/signbyte/signflow/clients"
)

// TestPermittedFlows pins each login method to the flows it may drive.
func TestPermittedFlows(t *testing.T) {
	cases := map[string][]string{
		"webEid":          {"webEid"},
		"eidScan":         {"eidScan"},
		"eparakstsMobile": {"eparakstsMobile", "eparakstsMobileEseal", "csc"},
		"":                nil,
		"unknown":         nil,
	}
	for method, want := range cases {
		got := permittedFlows(method)
		if len(got) != len(want) {
			t.Fatalf("permittedFlows(%q) = %v, want %v", method, got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("permittedFlows(%q) = %v, want %v", method, got, want)
			}
		}
	}
}

// TestCheckBinding covers the permitted pairs, the cross pairs, and the
// fail-closed cases (empty and unknown methods permit nothing).
func TestCheckBinding(t *testing.T) {
	cases := []struct {
		name    string
		method  string
		flow    string
		wantErr bool
	}{
		{"webEid permits webEid", "webEid", "webEid", false},
		{"eidScan permits eidScan", "eidScan", "eidScan", false},
		{"eparakstsMobile permits its personal flow", "eparakstsMobile", "eparakstsMobile", false},
		{"eparakstsMobile permits the eSeal flow", "eparakstsMobile", "eparakstsMobileEseal", false},
		{"eparakstsMobile permits csc", "eparakstsMobile", "csc", false},

		{"webEid does not permit eidScan", "webEid", "eidScan", true},
		{"eidScan does not permit webEid", "eidScan", "webEid", true},
		{"eparakstsMobile does not permit webEid", "eparakstsMobile", "webEid", true},
		{"webEid does not permit csc", "webEid", "csc", true},

		{"empty method fails closed", "", "webEid", true},
		{"unknown method fails closed", "nope", "webEid", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkBinding(tc.method, tc.flow)
			if tc.wantErr && !errors.Is(err, ErrBindingMismatch) {
				t.Fatalf("checkBinding(%q,%q) = %v, want ErrBindingMismatch", tc.method, tc.flow, err)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("checkBinding(%q,%q) = %v, want nil", tc.method, tc.flow, err)
			}
		})
	}
}

// TestBeginRejectsMismatchedBindingBeforeAnyProviderCall proves the gate runs
// before any collaborator work: a flow the login method does not permit is
// rejected with no document or provider call.
func TestBeginRejectsMismatchedBindingBeforeAnyProviderCall(t *testing.T) {
	signer := &fakeSigner{}
	docs := &fakeDocs{}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.LoginMethod = "webEid" // a Web eID login...
	in.Flow = "eidScan"       // ...cannot drive an eID Scan signing

	_, err := c.Begin(context.Background(), in)
	if !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("expected ErrBindingMismatch, got %v", err)
	}
	if docs.metaCalls != 0 || signer.prepareCalls != 0 {
		t.Fatalf("collaborators called for a mismatched binding: meta=%d prepare=%d", docs.metaCalls, signer.prepareCalls)
	}
}

// TestBeginRejectsEmptyBinding proves an empty login method fails closed.
func TestBeginRejectsEmptyBinding(t *testing.T) {
	signer := &fakeSigner{}
	docs := &fakeDocs{}
	c, _ := newConductor(signer, docs)

	in := beginInput()
	in.LoginMethod = ""

	if _, err := c.Begin(context.Background(), in); !errors.Is(err, ErrBindingMismatch) {
		t.Fatalf("expected ErrBindingMismatch for an empty method, got %v", err)
	}
	if signer.prepareCalls != 0 {
		t.Fatalf("prepared a job under an empty binding")
	}
}

// TestBeginPersistsBinding proves the login method + LoA are saved on the job.
func TestBeginPersistsBinding(t *testing.T) {
	signer := &fakeSigner{prepare: mustPrepareWithURL("job-1", "eparakstsMobile", "AWAITING_AUTHORIZATION", "https://idp/x")}
	docs := &fakeDocs{meta: &clients.Meta{ID: "doc-1", Filename: "c.pdf", ContentHash: "h"}}
	c, st := newConductor(signer, docs)

	if _, err := c.Begin(context.Background(), beginInput()); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	job, err := st.GetJob(context.Background(), "job-1")
	if err != nil {
		t.Fatalf("job not saved: %v", err)
	}
	if job.LoginMethod != "eparakstsMobile" || job.LoA != "high" {
		t.Fatalf("binding not persisted on job: login_method=%q loa=%q", job.LoginMethod, job.LoA)
	}
}
