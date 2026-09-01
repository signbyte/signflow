package signflow

import (
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/signbyte/signflow/orchestrator"
	"github.com/signbyte/signflow/store"
)

func TestTestAppDefaultsHaveNoCollaboratorsAndMemoryStore(t *testing.T) {
	app := TestApp(t)

	qt.Assert(t, qt.IsNil(app.Store().Ping(app.BackgroundContext())))
	qt.Assert(t, qt.IsNil(app.OutboundClient())) // no collaborator base URLs configured
	qt.Assert(t, qt.IsNil(app.Conductor()))      // signer + document base URLs unset
	qt.Assert(t, qt.IsNotNil(app.Audit()))       // no-op recorder, but never nil
	qt.Assert(t, qt.IsNotNil(app.AuthMiddleware()))
}

func TestConfigReturnsLoadedConfiguration(t *testing.T) {
	app := TestApp(t)

	cfg := app.Config()
	qt.Assert(t, qt.IsNotNil(cfg))
	qt.Assert(t, qt.Equals(cfg.ServiceName, "signflow"))
}

func TestConfigPanicsWhenNotLoaded(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected Config() to panic on an unloaded App")
		}
	}()

	(&App{}).Config()
}

func TestSetAuthMiddlewareOverride(t *testing.T) {
	app := TestApp(t)

	mw := TestAuthMiddleware()
	app.SetAuthMiddleware(mw)
	qt.Assert(t, qt.IsNotNil(app.AuthMiddleware()))
}

func TestSetConductorInjectsConductor(t *testing.T) {
	app := TestApp(t)
	qt.Assert(t, qt.IsNil(app.Conductor()))

	c := orchestrator.New(store.NewMemory(), nil, nil, nil)
	app.SetConductor(c)
	qt.Assert(t, qt.Equals(app.Conductor(), c))
}
