package bundle

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

type KeyStore interface {
	FindJWTKey(trustDomainID, keyID string) (crypto.PublicKey, error)
}

// Bundle holds a x509 and JWT bundles for a specific trust domain ID
type Bundle struct {
	// the SPIFFE ID of the trust domain the bundle belongs to
	TrustDomainID string
	// list of root CA certificates
	RootCAs []*x509.Certificate
	// list of JWT signing keys
	JWTKeys map[string]crypto.PublicKey
	// refresh hint is a hint, in seconds, on how often a bundle consumer
	// should poll for bundle updates
	RefreshHint int
}

// New creates a bundle with a trust domain ID
func New(trustDomainID string) *Bundle {
	return &Bundle{
		TrustDomainID: trustDomainID,
		JWTKeys:       make(map[string]crypto.PublicKey),
	}
}

// map of bundles keyed by trustDomainID
type Bundles map[string]*Bundle

// FindJWTKey find a JWT Key by trustDomainID and key
func (b Bundles) FindJWTKey(trustDomainID, keyID string) (crypto.PublicKey, error) {
	bundle, ok := b[trustDomainID]
	if !ok {
		return nil, fmt.Errorf("no keys found for trust domain %q", trustDomainID)
	}
	publicKey, ok := bundle.JWTKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("public key %q not found in trust domain %q", keyID, trustDomainID)
	}
	return publicKey, nil
}
