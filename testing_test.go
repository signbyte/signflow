package signflow

import (
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// probeAuthMiddleware wires TestAuthMiddleware in front of a route that
// captures the resulting user, so its branches can be exercised over real
// requests (a mock context has no request to read headers from).
func probeAuthMiddleware(t *testing.T) (*azugo.TestApp, *azugo.User) {
	t.Helper()

	app := azugo.NewTestApp()
	var captured azugo.User
	app.Use(TestAuthMiddleware())
	app.Get("/t", func(ctx *azugo.Context) {
		u := ctx.User()
		captured = u
		ctx.StatusCode(fasthttp.StatusNoContent)
	})
	app.Start(t)
	t.Cleanup(app.Stop)

	return app, &captured
}

func TestTestAuthMiddlewareRejectsMissingScopes(t *testing.T) {
	app, _ := probeAuthMiddleware(t)

	resp, err := app.TestClient().Get("/t")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

func TestTestAuthMiddlewareDefaultsSubject(t *testing.T) {
	app, captured := probeAuthMiddleware(t)

	tc := app.TestClient()
	resp, err := tc.Get("/t", tc.WithHeader("X-Test-Scopes", "signatures:create"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(resp)

	u := *captured
	qt.Assert(t, qt.Equals(u.ID(), "svc:test-client"))
	qt.Assert(t, qt.IsTrue(u.HasScopeLevel("signatures", "create")))
}

func TestTestAuthMiddlewareSetsClaimsFromHeaders(t *testing.T) {
	app, captured := probeAuthMiddleware(t)

	tc := app.TestClient()
	resp, err := tc.Get("/t",
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("X-Test-Sub", "user-1"),
		tc.WithHeader("X-Test-Login-Method", "eparakstsMobile"),
		tc.WithHeader("X-Test-LoA", "high"),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusNoContent))
	fasthttp.ReleaseResponse(resp)

	u := *captured
	qt.Assert(t, qt.Equals(u.ID(), "user-1"))
	qt.Assert(t, qt.Equals(u.ClaimValue("login_method"), "eparakstsMobile"))
	qt.Assert(t, qt.Equals(u.ClaimValue("loa"), "high"))
}
