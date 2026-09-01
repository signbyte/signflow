package signflow

import (
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/spf13/viper"

	"github.com/gmb-lib/go-authbyte/authclient"
)

func TestOutboundEnabled(t *testing.T) {
	qt.Assert(t, qt.IsFalse((&Configuration{}).OutboundEnabled()))
	qt.Assert(t, qt.IsTrue((&Configuration{SignerBaseURL: "http://signer"}).OutboundEnabled()))
	qt.Assert(t, qt.IsTrue((&Configuration{DocumentBaseURL: "http://document"}).OutboundEnabled()))
	qt.Assert(t, qt.IsTrue((&Configuration{EnvelopeBaseURL: "http://envelope"}).OutboundEnabled()))
	qt.Assert(t, qt.IsFalse((&Configuration{SignerBaseURL: "  "}).OutboundEnabled()))
}

func TestStorePostgres(t *testing.T) {
	qt.Assert(t, qt.IsFalse((&Configuration{}).StorePostgres()))
	qt.Assert(t, qt.IsTrue((&Configuration{StoreDSN: "postgres://x"}).StorePostgres()))
}

func TestConductorReady(t *testing.T) {
	qt.Assert(t, qt.IsFalse((&Configuration{}).ConductorReady()))
	qt.Assert(t, qt.IsFalse((&Configuration{SignerBaseURL: "http://signer"}).ConductorReady()))
	qt.Assert(t, qt.IsFalse((&Configuration{DocumentBaseURL: "http://document"}).ConductorReady()))
	qt.Assert(t, qt.IsTrue((&Configuration{SignerBaseURL: "http://signer", DocumentBaseURL: "http://document"}).ConductorReady()))
}

func TestEnvelopeReady(t *testing.T) {
	qt.Assert(t, qt.IsFalse((&Configuration{}).EnvelopeReady()))
	qt.Assert(t, qt.IsTrue((&Configuration{EnvelopeBaseURL: "http://envelope"}).EnvelopeReady()))
}

func TestOutboundIssuerDefaultsToAuthIssuer(t *testing.T) {
	c := &Configuration{Auth: &authclient.Configuration{IssuerURL: "https://auth.example"}}
	qt.Assert(t, qt.Equals(c.outboundIssuer(), "https://auth.example"))
}

func TestOutboundIssuerOverride(t *testing.T) {
	c := &Configuration{
		Auth:              &authclient.Configuration{IssuerURL: "https://auth.example"},
		OutboundIssuerURL: "https://outbound.example",
	}
	qt.Assert(t, qt.Equals(c.outboundIssuer(), "https://outbound.example"))
}

func TestOutboundAuthClientConfigCopiesAndOverrides(t *testing.T) {
	c := &Configuration{
		Auth:                &authclient.Configuration{IssuerURL: "https://auth.example", ServiceAudience: "svc:signflow"},
		ServiceClientID:     "svc:signflow",
		ServiceClientSecret: "s3cr3t",
	}

	out := c.OutboundAuthClientConfig()
	qt.Assert(t, qt.Equals(out.IssuerURL, "https://auth.example"))
	qt.Assert(t, qt.Equals(out.ServiceAudience, "svc:signflow"))
	qt.Assert(t, qt.Equals(out.ServiceClientID, "svc:signflow"))
	qt.Assert(t, qt.Equals(out.ServiceClientSecret, "s3cr3t"))

	// The returned config is a copy — mutating it must not affect c.Auth.
	out.ServiceAudience = "mutated"
	qt.Assert(t, qt.Equals(c.Auth.ServiceAudience, "svc:signflow"))
}

func TestNewConfigurationBindsBaseConfiguration(t *testing.T) {
	c := NewConfiguration()
	qt.Assert(t, qt.IsNotNil(c.BaseConfiguration))
	qt.Assert(t, qt.IsNotNil(c.ServerCore()))
}

func TestBindRegistersDefaults(t *testing.T) {
	c := NewConfiguration()
	v := viper.New()

	c.Bind("", v)

	qt.Assert(t, qt.Equals(v.GetString("signer_audience"), "svc:eparaksts-signer"))
	qt.Assert(t, qt.Equals(v.GetString("document_audience"), "svc:document"))
	qt.Assert(t, qt.Equals(v.GetString("envelope_audience"), "svc:envelope"))
	qt.Assert(t, qt.Equals(v.GetString("service_client_id"), "svc:signflow"))
	qt.Assert(t, qt.Equals(v.GetString("eidas_audit_topic"), "audit.signing"))
	qt.Assert(t, qt.IsNotNil(c.Auth))
}
