package audit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// fakeDrainable records Drain/Close calls so the Tasker adapter can be tested
// without a real eIDAS-audit Emitter.
type fakeDrainable struct {
	drainCalled chan context.Context
	closeErr    error
	closeCalled chan struct{}
}

func newFakeDrainable() *fakeDrainable {
	return &fakeDrainable{
		drainCalled: make(chan context.Context, 1),
		closeCalled: make(chan struct{}, 1),
	}
}

func (f *fakeDrainable) Drain(ctx context.Context) {
	f.drainCalled <- ctx
	<-ctx.Done()
}

func (f *fakeDrainable) Close(_ context.Context) error {
	f.closeCalled <- struct{}{}

	return f.closeErr
}

func TestDrainTaskName(t *testing.T) {
	task := NewEmitterDrainTask("eidas-audit-drain", newFakeDrainable())
	qt.Assert(t, qt.Equals(task.Name(), "eidas-audit-drain"))
}

func TestDrainTaskStartRunsDrainInBackground(t *testing.T) {
	client := newFakeDrainable()
	task := NewEmitterDrainTask("t", client)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	qt.Assert(t, qt.IsNil(task.Start(ctx)))

	select {
	case gotCtx := <-client.drainCalled:
		qt.Assert(t, qt.Equals(gotCtx, ctx))
	case <-time.After(2 * time.Second):
		t.Fatal("Drain was not called")
	}
}

func TestDrainTaskStopClosesClient(t *testing.T) {
	client := newFakeDrainable()
	task := NewEmitterDrainTask("t", client)

	task.Stop()

	select {
	case <-client.closeCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close was not called")
	}
}

func TestDrainTaskStopIgnoresCloseError(t *testing.T) {
	client := newFakeDrainable()
	client.closeErr = errors.New("close failed")
	task := NewEmitterDrainTask("t", client)

	// Must not panic even though Close returns an error.
	task.Stop()

	select {
	case <-client.closeCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close was not called")
	}
}
