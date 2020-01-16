package svid

import (
	"crypto"
	"crypto/x509"
	"fmt"
)

type Bundle struct {
	TrustDomainID  string
	RootCAs        []*x509.Certificate
	JwtSigningKeys map[string]crypto.PublicKey
}

func NewBundle(trustDomainID string) *Bundle {
	return &Bundle{
		TrustDomainID:  trustDomainID,
		JwtSigningKeys: make(map[string]crypto.PublicKey),
	}
}

type Bundles map[string]*Bundle

func (b Bundles) FindPublicKey(trustDomainID, keyID string) (crypto.PublicKey, error) {
	bundle, ok := b[trustDomainID]
	if ok {
		return nil, fmt.Errorf("no keys found for trust domain %q", trustDomainID)
	}
	publicKey, ok := bundle.JwtSigningKeys[keyID]
	if !ok {
		return nil, fmt.Errorf("public key %q not found in trust domain %q", keyID, trustDomainID)
	}
	return publicKey, nil
}
