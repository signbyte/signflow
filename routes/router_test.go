package routes

import (
	"testing"

	api "github.com/signbyte/signflow"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

func testApp(t testing.TB) *azugo.TestApp {
	app := api.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

func TestHealthzOK(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

func TestSigningsRequireAuth(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/api/v1/signings", []byte("{}"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// With a valid (test) service token the route is reached, but the test app wires
// no collaborators, so the conductor guard reports not-ready (503) — proving auth +
// routing + the guard are wired.
func TestSigningsAuthorizedNotReady(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signings", []byte("{}"), tc.WithHeader("X-Test-Scopes", "signatures:create"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
	fasthttp.ReleaseResponse(resp)
}

// The validations route is wired + authenticated; with no collaborators the
// conductor guard reports not-ready (503), proving auth + routing + the guard.
func TestValidateAuthorizedNotReady(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/validations", []byte(`{"signatureId":"x"}`), tc.WithHeader("X-Test-Scopes", "signatures:read"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusServiceUnavailable))
	fasthttp.ReleaseResponse(resp)
}
