package bundle

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

type KeyStore interface {
	FindJWTKey(trustDomainID, kid string) (crypto.PublicKey, error)
}

type Bundle struct {
	TrustDomainID string
	RootCAs       []*x509.Certificate
	JWTKeys       map[string]crypto.PublicKey
	RefreshHint   int
}

func New(trustDomainID string) *Bundle {
	return &Bundle{
		TrustDomainID: trustDomainID,
		JWTKeys:       make(map[string]crypto.PublicKey),
	}
}

type Bundles map[string]*Bundle

func (b Bundles) FindJWTKeys(trustDomainID, keyID string) (crypto.PublicKey, error) {
	bundle, ok := b[trustDomainID]
	if ok {
		return nil, fmt.Errorf("no keys found for trust domain %q", trustDomainID)
	}
	publicKey, ok := bundle.JWTKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("public key %q not found in trust domain %q", keyID, trustDomainID)
	}
	return publicKey, nil
}
