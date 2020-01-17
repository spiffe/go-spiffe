// Package spiffe has been deprecated, use the specific package
// under the spiffe directory instead
package spiffe

import (
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
	GetIDsFromCertificate       = spiffeid.GetIDsFromCertificate
	MatchID                     = spiffeid.MatchID
	NormalizeID                 = spiffeid.NormalizeID
	NormalizeURI                = spiffeid.NormalizeURI
	ParseID                     = spiffeid.ParseID
	TrustDomainID               = spiffeid.TrustDomainID
	TrustDomainURI              = spiffeid.TrustDomainURI
	ValidateID                  = spiffeid.ValidateID
	ValidateURI                 = spiffeid.ValidateURI
	VerifyCertificate           = spiffeid.VerifyCertificate
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
	ExpectAnyPeer      = x509svid.ExpectAnyPeer
	ExpectPeer         = x509svid.ExpectPeer
	ExpectPeerInDomain = x509svid.ExpectPeerInDomain
	ExpectPeers        = x509svid.ExpectPeers
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
