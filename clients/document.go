package clients

import (
	"bytes"
	"context"
	"fmt"
	"mime/multipart"
	"net/http"
	"strings"
)

// Documents is the client for the document service — the platform's owner of
// document bytes, canonical hashes, and ASiC-E assembly. signflow fetches only
// metadata (byte-free) and hands back the fileless container for completion; the
// bytes themselves never transit signflow for the hash-only XAdES path.
type Documents struct {
	doer     Doer
	baseURL  string
	audience string
}

// NewDocuments builds a document-service client over the given outbound doer.
func NewDocuments(d Doer, baseURL, audience string) *Documents {
	return &Documents{doer: d, baseURL: strings.TrimRight(baseURL, "/"), audience: audience}
}

const (
	scopeDocRead  = "documents:read"
	scopeDocWrite = "documents:write"
)

// Meta is the document-metadata projection signflow needs: the canonical hash to
// sign and the filename used as the data-object name when the container is built.
// Kind distinguishes a plain source document from an ASiC-E container (the latter
// is co-signed: its inner files are signed, not the container blob).
type Meta struct {
	ID                string `json:"id"`
	Kind              string `json:"kind"` // source | container
	Filename          string `json:"filename"`
	Mime              string `json:"mime"`
	ContentHash       string `json:"contentHash"`
	PreservationClass string `json:"preservationClass"`
}

// ChainHead is a chain's current live signed head — the artifact a co-signer must
// sign on top of. ID is empty when no signed head exists yet (the chain is still just
// its source, so the caller signs the root). Kind is "pdf" (PAdES) or "container".
type ChainHead struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	ContentHash string `json:"contentHash"`
}

// CurrentHead resolves a chain's current live signed head by its ROOT id — the
// server-authoritative artifact a co-signer must sign on top of, never a stale
// client-supplied id. An empty ID means no signed head yet (the caller signs the
// root/source). Acts on behalf of the signing user (chain-ACL authorized).
func (c *Documents) CurrentHead(ctx context.Context, rootID string, obo OnBehalf) (*ChainHead, error) {
	url := fmt.Sprintf("%s/api/v1/documents/%s/head", c.baseURL, rootID)

	var out ChainHead
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// DataObject is one inner file of an ASiC-E container being co-signed: the
// in-container filename and its canonical digest.
type DataObject struct {
	Name        string `json:"name"`
	ContentHash string `json:"contentHash"`
	Algorithm   string `json:"algorithm"`
}

type dataObjectsResponse struct {
	ContainerID string       `json:"containerId"`
	DataObjects []DataObject `json:"dataObjects"`
}

// Container is the result of completing or assembling a container.
type Container struct {
	ContainerID string `json:"containerId"`
	ContentHash string `json:"contentHash"`
}

// Metadata fetches a document's metadata, including its canonical hash and the
// filename. No bytes are returned — byte ownership stays in the document service.
// The call acts on behalf of the signing user, so the user's own document is
// reachable (the document service owner-filters on the user subject).
func (c *Documents) Metadata(ctx context.Context, id string, obo OnBehalf) (*Meta, error) {
	url := fmt.Sprintf("%s/api/v1/documents/%s", c.baseURL, id)

	var out Meta
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Content fetches a document's full bytes. Used for validation, where the whole
// signed container must be sent to the provider (there is no hash-only validation
// path). This is a deliberate byte transit for the validate operation — distinct
// from the byte-free hash-only signing path. Acts on behalf of the signing user.
func (c *Documents) Content(ctx context.Context, id string, obo OnBehalf) ([]byte, error) {
	if obo.Token == "" {
		return nil, fmt.Errorf("document: content: missing on-behalf-of subject token")
	}

	// conduit=signing declares the platform purpose: the orchestrator fetches
	// bytes to merge a co-signature, validate, or archive — the fetch must keep
	// working while the chain's signed result is download-frozen mid-workflow
	// (an undeclared consumer fails closed under the freeze).
	url := fmt.Sprintf("%s/api/v1/documents/%s/content?conduit=signing", c.baseURL, id)

	resp, err := c.doer.DoServiceOnBehalf(ctx, c.audience, scopeDocRead, obo.Sub, obo.Token, http.MethodGet, url, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("document: content: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &HTTPError{Service: "document", StatusCode: resp.StatusCode, Body: string(resp.Body)}
	}

	return resp.Body, nil
}

// DataObjects fetches a container's inner data objects (name + canonical digest)
// so the conductor can register them for a parallel co-signature — a co-signature
// signs the container's inner files, not the container blob as a whole. Acts on
// behalf of the signing user.
func (c *Documents) DataObjects(ctx context.Context, id string, obo OnBehalf) ([]DataObject, error) {
	url := fmt.Sprintf("%s/api/v1/documents/%s/data-objects", c.baseURL, id)

	var out dataObjectsResponse
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocRead, http.MethodGet, url, obo, nil, "", &out); err != nil {
		return nil, err
	}

	return out.DataObjects, nil
}

// SignedDoc is the document service's response to storing a finished signed
// document (a PDF signed in place): its new id + canonical hash.
type SignedDoc struct {
	SignedDocumentID string `json:"signedDocumentId"`
	ContentHash      string `json:"contentHash"`
}

// StoreSignedDocument stores a finished, opaque signed document (a PAdES-signed
// PDF) against its chain and returns its id + canonical hash. Unlike Complete
// (which fills a fileless ASiC-E container) the artifact is stored verbatim — there
// is no container to assemble; integrity is the embedded signature. Acts on behalf
// of the signing user. A concurrent second signed document surfaces as
// chain-advanced (an embedded PDF signature can't be merged — re-sign the current).
func (c *Documents) StoreSignedDocument(ctx context.Context, parentID string, signed []byte, mime, filename string, obo OnBehalf) (*SignedDoc, error) {
	if filename == "" {
		filename = "signed.pdf"
	}

	body, contentType, err := multipartFileFields("signed", filename, signed, map[string]string{"mime": mime})
	if err != nil {
		return nil, fmt.Errorf("document: build signed multipart: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/documents/%s/signed", c.baseURL, parentID)

	var out SignedDoc
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodPost, url, obo, body, contentType, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// ArchivedDoc is the result of storing a document's archive-timestamped form:
// the SAME document id, now pointing at the archived bytes.
type ArchivedDoc struct {
	ID          string `json:"id"`
	ContentHash string `json:"contentHash"`
	Mime        string `json:"mime"`
	Size        int64  `json:"size"`
}

// StoreArchived replaces a signed head's bytes in place with its
// archive-timestamped form (B-LT → B-LTA): the same document, refreshed — never
// a new row. Acts on behalf of the user; the document service CAS-guards the
// swap, so a concurrent co-sign surfaces as chain-advanced and the caller
// retries on the new head.
func (c *Documents) StoreArchived(ctx context.Context, id string, archived []byte, filename string, obo OnBehalf) (*ArchivedDoc, error) {
	if filename == "" {
		filename = "archived"
	}

	body, contentType, err := multipartFile("archived", filename, archived)
	if err != nil {
		return nil, fmt.Errorf("document: build archived multipart: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/documents/%s/archived", c.baseURL, id)

	var out ArchivedDoc
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodPost, url, obo, body, contentType, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// Complete fills the provider's fileless container with the stored source bytes,
// has the document service self-check the digest references, store the result, and
// return its id + canonical hash. Acts on behalf of the signing user.
func (c *Documents) Complete(ctx context.Context, id string, fileless []byte, obo OnBehalf) (*Container, error) {
	body, contentType, err := multipartFile("container", "fileless.asice", fileless)
	if err != nil {
		return nil, fmt.Errorf("document: build multipart: %w", err)
	}

	url := fmt.Sprintf("%s/api/v1/documents/%s/complete", c.baseURL, id)

	var out Container
	if err := doJSONOnBehalf(ctx, c.doer, "document", c.audience, scopeDocWrite, http.MethodPost, url, obo, body, contentType, &out); err != nil {
		return nil, err
	}

	return &out, nil
}

// multipartFile builds a single-file multipart/form-data body and its Content-Type.
func multipartFile(field, filename string, data []byte) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	part, err := w.CreateFormFile(field, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), w.FormDataContentType(), nil
}

// multipartFileFields builds a multipart/form-data body with one file part plus
// text fields (e.g. a `mime` field alongside the signed document bytes).
func multipartFileFields(fileField, filename string, data []byte, fields map[string]string) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	for k, v := range fields {
		if err := w.WriteField(k, v); err != nil {
			return nil, "", err
		}
	}
	part, err := w.CreateFormFile(fileField, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err := part.Write(data); err != nil {
		return nil, "", err
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), w.FormDataContentType(), nil
}

// multipartMetaFiles builds a multipart/form-data body with one JSON metadata text
// field plus a file part per files entry (field name = filename = the map key),
// used for the byte-conduit prepare (a JSON `metadata` part + the document bytes).
func multipartMetaFiles(metaField, metaJSON string, files map[string][]byte) ([]byte, string, error) {
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)

	if err := w.WriteField(metaField, metaJSON); err != nil {
		return nil, "", err
	}
	for ref, data := range files {
		part, err := w.CreateFormFile(ref, ref)
		if err != nil {
			return nil, "", err
		}
		if _, err := part.Write(data); err != nil {
			return nil, "", err
		}
	}
	if err := w.Close(); err != nil {
		return nil, "", err
	}

	return buf.Bytes(), w.FormDataContentType(), nil
}
