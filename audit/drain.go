package audit

import (
	"context"
	"time"

	"azugo.io/core"
)

// drainable is the shutdown contract of a buffered audit emitter: a Drain loop
// that publishes spooled events in the background and a Close that stops it and
// flushes. The eIDAS-audit Emitter (with a durable outbox) satisfies it.
type drainable interface {
	Drain(ctx context.Context)
	Close(ctx context.Context) error
}

// drainTask runs a drainable's background outbox delivery as a core.Tasker, so
// buffered evidence delivers in the background and flushes on shutdown without an
// App.Start/Stop override.
type drainTask struct {
	name   string
	client drainable
}

// NewEmitterDrainTask returns a Tasker that drains a buffered audit emitter's
// outbox and flushes it on shutdown, under the given task name.
func NewEmitterDrainTask(name string, client drainable) core.Tasker {
	return &drainTask{name: name, client: client}
}

func (t *drainTask) Name() string { return t.name }

func (t *drainTask) Start(ctx context.Context) error {
	go t.client.Drain(ctx)

	return nil
}

func (t *drainTask) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = t.client.Close(ctx)
}
