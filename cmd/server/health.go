package main

import (
	app "github.com/signbyte/signflow"

	"azugo.io/azugo/server"
	"azugo.io/core/cli"
)

func init() {
	cli.Register(server.HealthCommand("/healthz", server.Options{
		AppName:       "Signing Orchestrator (signflow)",
		AppVer:        Version,
		Configuration: app.NewConfiguration(),
	}))
}
