package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// TLSClientConfig returns a TLS configuration which verifies and authorizes
// the server X509-SVID.
func TLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	panic("not implemented")
}

// HookTLSClientConfig sets up the TLS configuration to verify and authorize
// the server X509-SVID. If there is an existing callback set for
// VerifyPeerCertificate it will be wrapped by by this package and invoked
// after SPIFFE authentication has completed.
func HookTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	panic("not implemented")
}

// MTLSClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies and authorizes the server X509-SVID.
func MTLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	panic("not implemented")
}

// HookMTLSClientConfig sets up the TLS configuration to present an X509-SVID
// to the server and verify and authorize the server X509-SVID. If there is an
// existing callback set for VerifyPeerCertificate it will be wrapped by by
// this package and invoked after SPIFFE authentication has completed.
func HookMTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	panic("not implemented")
}

// MTLSWebClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies the server certificate using system roots.
func MTLSWebClientConfig(svid x509svid.Source) *tls.Config {
	panic("not implemented")
}

// HookMTLSWebClientConfig sets up the TLS configuration to present an
// X509-SVID to the server and verified the server certificate using system
// roots.
func HookMTLSWebClientConfig(config *tls.Config, svid x509svid.Source) {
	panic("not implemented")
}

// TLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and does not require or verify client certificates.
func TLSServerConfig(svid x509svid.Source) *tls.Config {
	panic("not implemented")
}

// HookTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and to not require or verify client certificates.
func HookTLSServerConfig(config *tls.Config, svid x509svid.Source) {
	panic("not implemented")
}

// MTLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and requires, verifies, and authorizes client X509-SVIDs.
func MTLSServerConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	panic("not implemented")
}

// HookMTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and require, verify, and authorize the client X509-SVID. If
// there is an existing callback set for VerifyPeerCertificate it will be
// wrapped by by this package and invoked after SPIFFE authentication has
// completed.
func HookMTLSServerConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	panic("not implemented")
}

// MTLSWebServerConfig returns a TLS configuration which presents a web
// server certificate to the client and requires, verifies, and authorizes
// client X509-SVIDs.
func MTLSWebServerConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	panic("not implemented")
}

// HookMTLSWebServerConfig sets up the TLS configuration to presents a web
// server certificate to the client and require, verify, and authorize client
// X509-SVIDs. If there is an existing callback set for VerifyPeerCertificate
// it will be wrapped by by this package and invoked after SPIFFE
// authentication has completed.
func HookMTLSWebServerConfig(config *tls.Config, cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) {
	panic("not implemented")
}

// GetCertificate returns a GetCertificate callback for tls.Config. It uses the
// given X509-SVID getter to obtain a server X509-SVID for the TLS handshake.
func GetCertificate(svid x509svid.Source) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	panic("not implemented")
}

// GetClientCertificate returns a GetClientCertificate callback for tls.Config.
// It uses the given X509-SVID getter to obtain a client X509-SVID for the TLS
// handshake.
func GetClientCertificate(svid x509svid.Source) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	panic("not implemented")
}

// VerifyPeerCertificate returns a VerifyPeerCertificate callback for
// tls.Config. It uses the given bundle source and authorizer to verify and
// authorize X509-SVIDs provided by peers during the TLS handshake.
func VerifyPeerCertificate(bundle x509bundle.Source, authorizer Authorizer) func([][]byte, [][]*x509.Certificate) error {
	panic("not implemented")
}
