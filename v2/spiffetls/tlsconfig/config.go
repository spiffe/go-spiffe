package tlsconfig

import (
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

type verifyPeerCertificate = func(raw [][]byte, certs [][]*x509.Certificate) error

func wrapVerifyPeerCertificate(wrapped, newVerifier verifyPeerCertificate) verifyPeerCertificate {
	if wrapped == nil {
		return newVerifier
	}

	return func(raw [][]byte, certs [][]*x509.Certificate) error {
		if err := newVerifier(raw, certs); err != nil {
			return err
		}
		return wrapped(raw, certs)
	}
}

// TLSClientConfig returns a TLS configuration which verifies and authorizes
// the server X509-SVID.
func TLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookTLSClientConfig(config, svid, bundle, authorizer)
	return config
}

// HookTLSClientConfig sets up the TLS configuration to verify and authorize
// the server X509-SVID. If there is an existing callback set for
// VerifyPeerCertificate it will be wrapped by by this package and invoked
// after SPIFFE authentication has completed.
func HookTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	config.InsecureSkipVerify = true
	config.GetCertificate = GetCertificate(svid)
	config.VerifyPeerCertificate = wrapVerifyPeerCertificate(config.VerifyPeerCertificate, VerifyPeerCertificate(bundle, authorizer))

	// Not used by clients
	config.ClientAuth = tls.NoClientCert
	config.GetClientCertificate = nil
	config.Certificates = nil
	config.RootCAs = nil
	config.NameToCertificate = nil
}

// MTLSClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies and authorizes the server X509-SVID.
func MTLSClientConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookMTLSClientConfig(config, svid, bundle, authorizer)
	return config
}

// HookMTLSClientConfig sets up the TLS configuration to present an X509-SVID
// to the server and verify and authorize the server X509-SVID. If there is an
// existing callback set for VerifyPeerCertificate it will be wrapped by by
// this package and invoked after SPIFFE authentication has completed.
func HookMTLSClientConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	config.InsecureSkipVerify = true
	config.GetCertificate = GetCertificate(svid)
	config.VerifyPeerCertificate = wrapVerifyPeerCertificate(config.VerifyPeerCertificate, VerifyPeerCertificate(bundle, authorizer))

	// Not used by clients
	config.ClientAuth = tls.NoClientCert
	config.GetClientCertificate = nil
	config.Certificates = nil
	config.RootCAs = nil
	config.NameToCertificate = nil
}

// MTLSWebClientConfig returns a TLS configuration which presents an X509-SVID
// to the server and verifies the server certificate using system roots.
func MTLSWebClientConfig(svid x509svid.Source) *tls.Config {
	config := new(tls.Config)
	HookMTLSWebClientConfig(config, svid)
	return config
}

// HookMTLSWebClientConfig sets up the TLS configuration to present an
// X509-SVID to the server and verified the server certificate using system
// roots.
func HookMTLSWebClientConfig(config *tls.Config, svid x509svid.Source) {
	config.InsecureSkipVerify = false
	config.GetCertificate = GetCertificate(svid)

	// Not used by clients
	config.ClientAuth = tls.NoClientCert
	config.GetClientCertificate = nil
	config.Certificates = nil
	config.RootCAs = nil
	config.NameToCertificate = nil
}

// TLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and does not require or verify client certificates.
func TLSServerConfig(svid x509svid.Source) *tls.Config {
	config := new(tls.Config)
	HookTLSServerConfig(config, svid)
	return config
}

// HookTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and to not require or verify client certificates.
func HookTLSServerConfig(config *tls.Config, svid x509svid.Source) {
	config.InsecureSkipVerify = false
	config.GetCertificate = GetCertificate(svid)

	// No required by server
	config.ClientAuth = tls.NoClientCert
	config.GetClientCertificate = nil
	config.Certificates = nil
	config.RootCAs = nil
	config.NameToCertificate = nil
}

// MTLSServerConfig returns a TLS configuration which presents an X509-SVID
// to the client and requires, verifies, and authorizes client X509-SVIDs.
func MTLSServerConfig(svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookMTLSServerConfig(config, svid, bundle, authorizer)
	return config
}

// HookMTLSServerConfig sets up the TLS configuration to present an X509-SVID
// to the client and require, verify, and authorize the client X509-SVID. If
// there is an existing callback set for VerifyPeerCertificate it will be
// wrapped by by this package and invoked after SPIFFE authentication has
// completed.
func HookMTLSServerConfig(config *tls.Config, svid x509svid.Source, bundle x509bundle.Source, authorizer Authorizer) {
	config.InsecureSkipVerify = true
	config.ClientAuth = tls.RequireAndVerifyClientCert
	config.GetCertificate = GetCertificate(svid)
	config.GetClientCertificate = GetClientCertificate(svid)
	config.VerifyPeerCertificate = wrapVerifyPeerCertificate(config.VerifyPeerCertificate, VerifyPeerCertificate(bundle, authorizer))

	// No required by server
	config.Certificates = nil
	config.RootCAs = nil
	config.NameToCertificate = nil
}

// MTLSWebServerConfig returns a TLS configuration which presents a web
// server certificate to the client and requires, verifies, and authorizes
// client X509-SVIDs.
func MTLSWebServerConfig(cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) *tls.Config {
	config := new(tls.Config)
	HookMTLSWebServerConfig(config, cert, bundle, authorizer)
	return config
}

// HookMTLSWebServerConfig sets up the TLS configuration to presents a web
// server certificate to the client and require, verify, and authorize client
// X509-SVIDs. If there is an existing callback set for VerifyPeerCertificate
// it will be wrapped by by this package and invoked after SPIFFE
// authentication has completed.
func HookMTLSWebServerConfig(config *tls.Config, cert *tls.Certificate, bundle x509bundle.Source, authorizer Authorizer) {
	config.InsecureSkipVerify = true
	config.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return cert, nil
	}
	config.VerifyPeerCertificate = wrapVerifyPeerCertificate(config.VerifyPeerCertificate, VerifyPeerCertificate(bundle, authorizer))

	// No required by server
	config.Certificates = nil
	config.RootCAs = nil
	config.NameToCertificate = nil
}

// GetCertificate returns a GetCertificate callback for tls.Config. It uses the
// given X509-SVID getter to obtain a server X509-SVID for the TLS handshake.
func GetCertificate(svid x509svid.Source) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return getTLSCertificate(svid)
	}
}

// GetClientCertificate returns a GetClientCertificate callback for tls.Config.
// It uses the given X509-SVID getter to obtain a client X509-SVID for the TLS
// handshake.
func GetClientCertificate(svid x509svid.Source) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return getTLSCertificate(svid)
	}
}

// VerifyPeerCertificate returns a VerifyPeerCertificate callback for
// tls.Config. It uses the given bundle source and authorizer to verify and
// authorize X509-SVIDs provided by peers during the TLS handshake.
func VerifyPeerCertificate(bundle x509bundle.Source, authorizer Authorizer) func([][]byte, [][]*x509.Certificate) error {
	return func(raw [][]byte, _ [][]*x509.Certificate) error {
		id, certs, err := x509svid.ParseAndVerify(raw, bundle)
		if err != nil {
			return err
		}

		return authorizer(id, certs)
	}
}

func getTLSCertificate(svid x509svid.Source) (*tls.Certificate, error) {
	s, err := svid.GetX509SVID()
	if err != nil {
		return nil, err
	}

	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(s.Certificates)),
		PrivateKey:  s.PrivateKey,
	}

	for _, svidCert := range s.Certificates {
		cert.Certificate = append(cert.Certificate, svidCert.Raw)
	}

	return cert, nil
}
