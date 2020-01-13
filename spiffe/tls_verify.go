package spiffe

import (
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/internal"
)

// verifyPeerCertificate verifies the provided peer certificate chain using the
// set trust domain roots.
func verifyPeerCertificate(peerChain []*x509.Certificate, trustDomainRoots map[string]*x509.CertPool) (string, [][]*x509.Certificate, error) {
	switch {
	case len(peerChain) == 0:
		return "", nil, errors.New("no peer certificates")
	case len(trustDomainRoots) == 0:
		return "", nil, errors.New("at least one trust domain root is required")
	}

	peer := peerChain[0]
	switch {
	case peer.IsCA:
		return "", nil, errors.New("cannot validate peer which is a CA")
	case peer.KeyUsage&x509.KeyUsageCertSign > 0:
		return "", nil, errors.New("cannot validate peer with KeyCertSign key usage")
	case peer.KeyUsage&x509.KeyUsageCRLSign > 0:
		return "", nil, errors.New("cannot validate peer with KeyCrlSign key usage")
	}
	peerID, trustDomainID, err := getIDsFromCertificate(peer)
	if err != nil {
		return "", nil, err
	}

	roots, ok := trustDomainRoots[trustDomainID]
	if !ok {
		return "", nil, fmt.Errorf("no roots for peer trust domain %q", trustDomainID)
	}

	verifiedChains, err := peer.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: internal.CertPoolFromCerts(peerChain[1:]),
		// TODO: assert client or server depending on role?
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return "", nil, err
	}

	return peerID, verifiedChains, nil
}

// VerifyPeerCertificate verifies the provided peer certificate chain using the
// set trust domain roots. The expectPeerFn callback is used to check the peer
// ID after the chain of trust has been verified to assert that the chain
// belongs to the intended peer.
func VerifyPeerCertificate(peerChain []*x509.Certificate, trustDomainRoots map[string]*x509.CertPool, expectPeerFn ExpectPeerFunc) ([][]*x509.Certificate, error) {
	if expectPeerFn == nil {
		return nil, errors.New("expectPeerFn callback is required")
	}

	peerID, verifiedChains, err := verifyPeerCertificate(peerChain, trustDomainRoots)
	if err != nil {
		return nil, err
	}

	if err := expectPeerFn(peerID, verifiedChains); err != nil {
		return nil, err
	}

	return verifiedChains, nil
}

// GetSpiffeIDFromX509 extracts the SPIFFE ID and verifies the provided peer certificate chain using the
// set trust domain root.
func GetSpiffeIDFromX509(peerChain []*x509.Certificate, trustBundle map[string]*x509.CertPool) (string, error) {
	peerID, _, err := verifyPeerCertificate(peerChain, trustBundle)
	if err != nil {
		return "", err
	}

	return peerID, nil
}
