package clients

import (
	"context"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-authbyte/authclient"
)

// doCall records one outbound call made through the fakeDoer.
type doCall struct {
	onBehalf bool
	timeout  time.Duration
	audience string
	scope    string
	sub      string
	token    string
	method   string
	url      string
	header   http.Header
	body     []byte
}

// fakeDoer scripts a single response/error for every call and records the
// calls made, so tests can assert on what clients sent without a real
// go-authbyte client or network.
type fakeDoer struct {
	resp  *authclient.BackgroundResponse
	err   error
	calls []doCall
}

func (f *fakeDoer) DoService(_ context.Context, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	f.calls = append(f.calls, doCall{audience: audience, scope: scope, method: method, url: fullURL, header: reqHeader, body: body})

	return f.resp, f.err
}

func (f *fakeDoer) DoServiceWithTimeout(_ context.Context, timeout time.Duration, audience, scope, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	f.calls = append(f.calls, doCall{timeout: timeout, audience: audience, scope: scope, method: method, url: fullURL, header: reqHeader, body: body})

	return f.resp, f.err
}

func (f *fakeDoer) DoServiceOnBehalf(_ context.Context, audience, scope, sub, token, method, fullURL string, reqHeader http.Header, body []byte) (*authclient.BackgroundResponse, error) {
	f.calls = append(f.calls, doCall{onBehalf: true, audience: audience, scope: scope, sub: sub, token: token, method: method, url: fullURL, header: reqHeader, body: body})

	return f.resp, f.err
}

func (f *fakeDoer) last() doCall { return f.calls[len(f.calls)-1] }

func okResp(body string) *authclient.BackgroundResponse {
	return &authclient.BackgroundResponse{StatusCode: 200, Body: []byte(body)}
}

// --- HTTPError ---

func TestHTTPErrorMessage(t *testing.T) {
	err := &HTTPError{Service: "signer", StatusCode: 502, Body: "bad gateway"}
	qt.Assert(t, qt.Equals(err.Error(), "signer: upstream status 502: bad gateway"))
}

// --- doJSON / doJSONOnBehalf ---

func TestDoJSONSuccessNoOut(t *testing.T) {
	d := &fakeDoer{resp: okResp("")}
	err := doJSON(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x/y", nil, "", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().method, http.MethodGet))
	qt.Assert(t, qt.Equals(d.last().url, "http://x/y"))
	qt.Assert(t, qt.Equals(d.last().header.Get("Content-Type"), ""))
}

func TestDoJSONSetsContentTypeWhenBodyPresent(t *testing.T) {
	d := &fakeDoer{resp: okResp("")}
	err := doJSON(context.Background(), d, "svc", "aud", "scope", http.MethodPost, "http://x", []byte("{}"), "application/json", nil)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().header.Get("Content-Type"), "application/json"))
}

func TestDoJSONDecodesOutput(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"a":"b"}`)}

	var out struct {
		A string `json:"a"`
	}
	err := doJSON(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x", nil, "", &out)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.A, "b"))
}

func TestDoJSONNon2xxReturnsHTTPError(t *testing.T) {
	d := &fakeDoer{resp: &authclient.BackgroundResponse{StatusCode: 404, Body: []byte("not found")}}
	err := doJSON(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x", nil, "", nil)

	var httpErr *HTTPError
	qt.Assert(t, qt.ErrorAs(err, &httpErr))
	qt.Assert(t, qt.Equals(httpErr.StatusCode, 404))
	qt.Assert(t, qt.Equals(httpErr.Service, "svc"))
}

func TestDoJSONDoerErrorWrapped(t *testing.T) {
	d := &fakeDoer{err: errors.New("boom")}
	err := doJSON(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x", nil, "", nil)
	qt.Assert(t, qt.ErrorMatches(err, "svc: boom"))
}

func TestDoJSONBadJSONReturnsDecodeError(t *testing.T) {
	d := &fakeDoer{resp: okResp("not-json")}

	var out struct{}
	err := doJSON(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x", nil, "", &out)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.StringContains(err.Error(), "decode response"))
}

func TestDoJSONOnBehalfMissingTokenFailsClosed(t *testing.T) {
	d := &fakeDoer{}
	err := doJSONOnBehalf(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x", OnBehalf{Sub: "u1"}, nil, "", nil)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.StringContains(err.Error(), "missing on-behalf-of subject token"))
	qt.Assert(t, qt.Equals(len(d.calls), 0))
}

func TestDoJSONOnBehalfSuccessThreadsIdentity(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"a":"b"}`)}

	var out struct {
		A string `json:"a"`
	}
	err := doJSONOnBehalf(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x", OnBehalf{Sub: "u1", Token: "tok"}, nil, "", &out)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.A, "b"))
	qt.Assert(t, qt.IsTrue(d.last().onBehalf))
	qt.Assert(t, qt.Equals(d.last().sub, "u1"))
	qt.Assert(t, qt.Equals(d.last().token, "tok"))
}

func TestDoJSONOnBehalfNon2xxReturnsHTTPError(t *testing.T) {
	d := &fakeDoer{resp: &authclient.BackgroundResponse{StatusCode: 403, Body: []byte("nope")}}
	err := doJSONOnBehalf(context.Background(), d, "svc", "aud", "scope", http.MethodGet, "http://x", OnBehalf{Sub: "u1", Token: "tok"}, nil, "", nil)

	var httpErr *HTTPError
	qt.Assert(t, qt.ErrorAs(err, &httpErr))
	qt.Assert(t, qt.Equals(httpErr.StatusCode, 403))
}

// --- Documents ---

func TestNewDocumentsTrimsTrailingSlash(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"id":"doc-1"}`)}
	docs := NewDocuments(d, "http://document/", "aud")

	_, err := docs.Metadata(context.Background(), "doc-1", OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().url, "http://document/api/v1/documents/doc-1"))
}

func TestDocumentsMetadataOnBehalfAndScope(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"id":"doc-1","kind":"source"}`)}
	docs := NewDocuments(d, "http://document", "aud")

	meta, err := docs.Metadata(context.Background(), "doc-1", OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(meta.Kind, "source"))
	qt.Assert(t, qt.Equals(d.last().scope, scopeDocRead))
	qt.Assert(t, qt.IsTrue(d.last().onBehalf))
}

func TestDocumentsContentMissingTokenFailsClosed(t *testing.T) {
	d := &fakeDoer{}
	docs := NewDocuments(d, "http://document", "aud")

	_, err := docs.Content(context.Background(), "doc-1", OnBehalf{Sub: "u1"})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Assert(t, qt.Equals(len(d.calls), 0))
}

func TestDocumentsContentSuccess(t *testing.T) {
	d := &fakeDoer{resp: okResp("raw-bytes")}
	docs := NewDocuments(d, "http://document", "aud")

	body, err := docs.Content(context.Background(), "doc-1", OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(body), "raw-bytes"))
	// The signing-conduit declaration keeps the fetch working while the chain's
	// signed result is download-frozen mid-workflow.
	qt.Assert(t, qt.Equals(d.last().url, "http://document/api/v1/documents/doc-1/content?conduit=signing"))
}

func TestDocumentsContentErrorStatus(t *testing.T) {
	d := &fakeDoer{resp: &authclient.BackgroundResponse{StatusCode: 500, Body: []byte("err")}}
	docs := NewDocuments(d, "http://document", "aud")

	_, err := docs.Content(context.Background(), "doc-1", OnBehalf{Sub: "u1", Token: "tok"})
	var httpErr *HTTPError
	qt.Assert(t, qt.ErrorAs(err, &httpErr))
	qt.Assert(t, qt.Equals(httpErr.StatusCode, 500))
}

func TestDocumentsDataObjects(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"containerId":"c1","dataObjects":[{"name":"a.pdf","contentHash":"h1"}]}`)}
	docs := NewDocuments(d, "http://document", "aud")

	objs, err := docs.DataObjects(context.Background(), "doc-1", OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(objs), 1))
	qt.Assert(t, qt.Equals(objs[0].Name, "a.pdf"))
	qt.Assert(t, qt.Equals(d.last().url, "http://document/api/v1/documents/doc-1/data-objects"))
}

func TestDocumentsCompleteBuildsMultipart(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"containerId":"c1","contentHash":"h1"}`)}
	docs := NewDocuments(d, "http://document", "aud")

	out, err := docs.Complete(context.Background(), "doc-1", []byte("fileless-bytes"), OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.ContainerID, "c1"))
	qt.Assert(t, qt.Equals(d.last().url, "http://document/api/v1/documents/doc-1/complete"))
	qt.Assert(t, qt.Equals(d.last().scope, scopeDocWrite))

	assertMultipartFile(t, d.last().header.Get("Content-Type"), d.last().body, "container", "fileless.asice", "fileless-bytes")
}

func TestDocumentsStoreSignedDocumentDefaultsFilename(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"signedDocumentId":"sd1","contentHash":"h1"}`)}
	docs := NewDocuments(d, "http://document", "aud")

	out, err := docs.StoreSignedDocument(context.Background(), "doc-1", []byte("pdf-bytes"), "application/pdf", "", OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(out.SignedDocumentID, "sd1"))

	assertMultipartFile(t, d.last().header.Get("Content-Type"), d.last().body, "signed", "signed.pdf", "pdf-bytes")
}

func TestDocumentsStoreSignedDocumentKeepsGivenFilename(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"signedDocumentId":"sd1"}`)}
	docs := NewDocuments(d, "http://document", "aud")

	_, err := docs.StoreSignedDocument(context.Background(), "doc-1", []byte("pdf-bytes"), "application/pdf", "contract.pdf", OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))

	assertMultipartFile(t, d.last().header.Get("Content-Type"), d.last().body, "signed", "contract.pdf", "pdf-bytes")
}

// --- Envelope ---

func TestEnvelopeMarkSlotSignedBuildsRequest(t *testing.T) {
	d := &fakeDoer{resp: okResp("")}
	env := NewEnvelope(d, "http://envelope/", "aud")

	err := env.MarkSlotSigned(context.Background(), "env-1", "slot-1", "sig-1", "ref-1", "job-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().url, "http://envelope/api/v1/envelopes/env-1/slots/slot-1/signed"))
	qt.Assert(t, qt.Equals(d.last().scope, scopeEnvelopeTransition))
	qt.Assert(t, qt.IsFalse(d.last().onBehalf))
	qt.Assert(t, qt.StringContains(string(d.last().body), `"signatureId":"sig-1"`))
	qt.Assert(t, qt.StringContains(string(d.last().body), `"jobId":"job-1"`))
}

func TestEnvelopeGetEnvelope(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"documents":[{"documentId":"doc-1"}],"slots":[]}`)}
	env := NewEnvelope(d, "http://envelope", "aud")

	view, err := env.GetEnvelope(context.Background(), "env-1", OnBehalf{Sub: "u1", Token: "tok"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(view.RootDocument(), "doc-1"))
	qt.Assert(t, qt.IsTrue(d.last().onBehalf))
	qt.Assert(t, qt.Equals(d.last().scope, scopeEnvelopeRead))
}

func TestEnvelopeViewRootDocumentEmpty(t *testing.T) {
	v := &EnvelopeView{}
	qt.Assert(t, qt.Equals(v.RootDocument(), ""))
}

// --- Signer ---

func TestSignerPrepareBuildsURLAndBody(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"jobId":"job-1","flow":"eparakstsMobile","state":"AWAITING_AUTHORIZATION"}`)}
	s := NewSigner(d, "http://signer", "aud")

	res, err := s.Prepare(context.Background(), "eparakstsMobile", []PrepareDoc{{DocumentID: "doc-1"}}, PrepareOptions{PostAuthRedirect: "https://x"})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.JobID, "job-1"))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/signatures/prepare?flow=eparakstsMobile"))
	qt.Assert(t, qt.Equals(d.last().scope, scopeSignCreate))
	qt.Assert(t, qt.StringContains(string(d.last().body), `"postAuthRedirect":"https://x"`))
}

func TestSignerPrepareWithFileBuildsMultipartMetadata(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"jobId":"job-1"}`)}
	s := NewSigner(d, "http://signer", "aud")

	files := map[string][]byte{"doc-1": []byte("pdf-bytes")}
	_, err := s.PrepareWithFile(context.Background(), "webEid", []PrepareDoc{{DocumentID: "doc-1", FileRef: "doc-1"}}, files, PrepareOptions{})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/signatures/prepare?flow=webEid"))

	mediaType, params, err := mime.ParseMediaType(d.last().header.Get("Content-Type"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.StringContains(mediaType, "multipart/form-data"))

	mr := multipart.NewReader(strings.NewReader(string(d.last().body)), params["boundary"])
	sawMeta, sawFile := false, false
	for {
		part, err := mr.NextPart()
		if err != nil {
			break
		}
		if part.FormName() == "metadata" {
			sawMeta = true
		}
		if part.FormName() == "doc-1" {
			sawFile = true
		}
	}
	qt.Assert(t, qt.IsTrue(sawMeta))
	qt.Assert(t, qt.IsTrue(sawFile))
}

func TestSignerStatusWithoutWait(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"jobId":"job-1","state":"DONE"}`)}
	s := NewSigner(d, "http://signer", "aud")

	_, err := s.Status(context.Background(), "job-1", 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/signatures/job-1/status"))
	qt.Assert(t, qt.Equals(d.last().scope, scopeSignRead))
}

func TestSignerStatusWithWait(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"jobId":"job-1"}`)}
	s := NewSigner(d, "http://signer", "aud")

	_, err := s.Status(context.Background(), "job-1", 30)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/signatures/job-1/status?wait=30"))
}

func TestSignerSubmit(t *testing.T) {
	d := &fakeDoer{resp: okResp(`{"jobId":"job-1","state":"SUBMITTED"}`)}
	s := NewSigner(d, "http://signer", "aud")

	res, err := s.Submit(context.Background(), "job-1", []ClientSignature{{DocumentID: "doc-1", SignatureValue: "sig"}})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(res.State, "SUBMITTED"))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/signatures/job-1/signatures"))
	qt.Assert(t, qt.Equals(d.last().scope, scopeSignWrite))
	qt.Assert(t, qt.StringContains(string(d.last().body), `"signatureValue":"sig"`))
}

func TestSignerValidateDefaultFilename(t *testing.T) {
	d := &fakeDoer{resp: okResp("report-bytes")}
	s := NewSigner(d, "http://signer", "aud")

	report, err := s.Validate(context.Background(), []byte("container-bytes"), "")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(report), "report-bytes"))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/validations"))

	assertMultipartFile(t, d.last().header.Get("Content-Type"), d.last().body, "file", "container.asice", "container-bytes")
}

func TestSignerValidateErrorStatus(t *testing.T) {
	d := &fakeDoer{resp: &authclient.BackgroundResponse{StatusCode: 422, Body: []byte("invalid")}}
	s := NewSigner(d, "http://signer", "aud")

	_, err := s.Validate(context.Background(), []byte("x"), "x.asice")
	var httpErr *HTTPError
	qt.Assert(t, qt.ErrorAs(err, &httpErr))
	qt.Assert(t, qt.Equals(httpErr.StatusCode, 422))
}

func TestSignerDownloadPAdESOmitsContainerParam(t *testing.T) {
	d := &fakeDoer{resp: okResp("pdf-bytes")}
	s := NewSigner(d, "http://signer", "aud")

	body, err := s.Download(context.Background(), "job-1", "doc-1", "PAdES")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(string(body), "pdf-bytes"))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/signatures/job-1/documents/doc-1"))
}

func TestSignerDownloadNonPAdESAddsContainerParam(t *testing.T) {
	d := &fakeDoer{resp: okResp("asice-bytes")}
	s := NewSigner(d, "http://signer", "aud")

	_, err := s.Download(context.Background(), "job-1", "doc-1", "XAdES")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(d.last().url, "http://signer/api/v1/signatures/job-1/documents/doc-1?container=asice"))
}

func TestSignerDownloadErrorStatus(t *testing.T) {
	d := &fakeDoer{resp: &authclient.BackgroundResponse{StatusCode: 404, Body: []byte("gone")}}
	s := NewSigner(d, "http://signer", "aud")

	_, err := s.Download(context.Background(), "job-1", "doc-1", "XAdES")
	var httpErr *HTTPError
	qt.Assert(t, qt.ErrorAs(err, &httpErr))
	qt.Assert(t, qt.Equals(httpErr.StatusCode, 404))
}

func TestPrepareResultAuthorizeURL(t *testing.T) {
	qt.Assert(t, qt.Equals((&PrepareResult{}).AuthorizeURL(), ""))

	p := &PrepareResult{Authorization: &authorization{AuthorizeURL: "https://idp/authorize"}}
	qt.Assert(t, qt.Equals(p.AuthorizeURL(), "https://idp/authorize"))
}

// --- multipart builders ---

func TestMultipartFileFieldsIncludesFields(t *testing.T) {
	body, contentType, err := multipartFileFields("signed", "out.pdf", []byte("bytes"), map[string]string{"mime": "application/pdf"})
	qt.Assert(t, qt.IsNil(err))

	mediaType, params, err := mime.ParseMediaType(contentType)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.StringContains(mediaType, "multipart/form-data"))

	mr := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
	form, err := mr.ReadForm(1 << 20)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(form.Value["mime"][0], "application/pdf"))
	qt.Assert(t, qt.Equals(len(form.File["signed"]), 1))
}

func TestMultipartMetaFilesIncludesMetaAndFiles(t *testing.T) {
	body, contentType, err := multipartMetaFiles("metadata", `{"a":1}`, map[string][]byte{"doc-1": []byte("bytes")})
	qt.Assert(t, qt.IsNil(err))

	_, params, err := mime.ParseMediaType(contentType)
	qt.Assert(t, qt.IsNil(err))

	mr := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
	form, err := mr.ReadForm(1 << 20)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(form.Value["metadata"][0], `{"a":1}`))
	qt.Assert(t, qt.Equals(len(form.File["doc-1"]), 1))
}

// assertMultipartFile parses a multipart body and checks that it contains a
// file part under the given field name with the given filename and content.
func assertMultipartFile(t *testing.T, contentType string, body []byte, field, filename, content string) {
	t.Helper()

	_, params, err := mime.ParseMediaType(contentType)
	qt.Assert(t, qt.IsNil(err))

	mr := multipart.NewReader(strings.NewReader(string(body)), params["boundary"])
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			t.Fatalf("multipart field %q not found", field)
		}
		qt.Assert(t, qt.IsNil(err))

		if part.FormName() != field {
			continue
		}

		qt.Assert(t, qt.Equals(part.FileName(), filename))

		data, err := io.ReadAll(part)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(string(data), content))

		return
	}
}
