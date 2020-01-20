// Package spiffe has been deprecated, use the specific package
// under the spiffe directory instead
package spiffe

import (
	"crypto/x509"

	"github.com/spiffe/go-spiffe/logger"
	"github.com/spiffe/go-spiffe/spiffe/spiffeid"
	"github.com/spiffe/go-spiffe/spiffe/svid/x509svid"
	"github.com/spiffe/go-spiffe/spiffe/tlspeer"
)

// Function aliases for the spiffeid package

var (
	AllowAny                    = spiffeid.AllowAny
	AllowAnyTrustDomain         = spiffeid.AllowAnyTrustDomain
	AllowAnyTrustDomainWorkload = spiffeid.AllowAnyTrustDomainWorkload
	AllowTrustDomain            = spiffeid.AllowTrustDomain
	AllowTrustDomainWorkload    = spiffeid.AllowTrustDomainWorkload
	NormalizeID                 = spiffeid.NormalizeID
	NormalizeURI                = spiffeid.NormalizeURI
	ParseID                     = spiffeid.ParseID
	TrustDomainID               = spiffeid.TrustDomainID
	TrustDomainURI              = spiffeid.TrustDomainURI
	ValidateID                  = spiffeid.ValidateID
	ValidateURI                 = spiffeid.ValidateURI
)

// Function aliases for the tlspeer package

var (
	AdaptGetCertificate        = tlspeer.AdaptGetCertificate
	AdaptGetClientCertificate  = tlspeer.AdaptGetClientCertificate
	AdaptVerifyPeerCertificate = tlspeer.AdaptVerifyPeerCertificate
	DialTLS                    = tlspeer.DialTLS
	ListenTLS                  = tlspeer.ListenTLS
	NewTLSPeer                 = tlspeer.NewTLSPeer
	VerifyPeerCertificate      = tlspeer.VerifyPeerCertificate
	WithLogger                 = tlspeer.WithLogger
	WithWorkloadAPIAddr        = tlspeer.WithWorkloadAPIAddr
)

// Function aliases for the x509svid package

var (
	ExpectAnyPeer         = x509svid.ExpectAnyPeer
	ExpectPeer            = x509svid.ExpectPeer
	ExpectPeerInDomain    = x509svid.ExpectPeerInDomain
	ExpectPeers           = x509svid.ExpectPeers
	GetIDsFromCertificate = x509svid.GetIDsFromCertificate
	MatchID               = x509svid.MatchID
)

// Type aliases for the x509svid package

type (
	ExpectPeerFunc = x509svid.ExpectPeerFunc
)

// Type aliases for the tlspeer package

type (
	TLSPeer       = tlspeer.TLSPeer
	TLSPeerOption = tlspeer.TLSPeerOption
)

// Type aliases for the logger package

type (
	Logger = logger.Logger
)

// VerifyCertificate has been deprecated, use VerifyPeerCertificate() from the
// tlspeer package instead.
// Verifies a SPIFFE certificate and its certification path. This function does
// not perform rich validation.
func VerifyCertificate(leaf *x509.Certificate, intermediates *x509.CertPool, roots *x509.CertPool) error {
	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         roots,
	}

	// TODO: SPIFFE-specific validation of leaf and verified chain
	_, err := leaf.Verify(verifyOpts)
	return err
}
