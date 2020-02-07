package jwtbundle

import (
	"crypto"
	"io"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Bundle is a collection of trusted JWT public keys for a trust domain.
type Bundle struct {
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	panic("not implemented")
}

// Load loads a Bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	panic("not implemented")
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	panic("not implemented")
}

// Parse parses a bundle from bytes.
func Parse(trustDomain spiffeid.TrustDomain, b []byte) (*Bundle, error) {
	panic("not implemented")
}

// TrustDomain returns the trust domain the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	panic("not implemented")
}

// JWTKeys returns the JWT keys in the bundle, keyed by key ID.
func (b *Bundle) JWTKeys() map[string]crypto.PublicKey {
	panic("not implemented")
}

// FindJWTKey finds the JWT key with the given key id from the bundle. If the key
// is found, it is returned and the boolean is true. Otherwise, the returned
// value is nil and the boolean is false.
func (b *Bundle) FindJWTKey(keyID string) (crypto.PublicKey, bool) {
	panic("not implemented")
}

// AddJWTKey adds a JWT key to the bundle. If a JWT key already exists
// under the given key ID, it is replaced.
func (b *Bundle) AddJWTKey(keyID string, key crypto.PublicKey) {
	panic("not implemented")
}

// RemoveJWTKey removes the JWT key identified by the key ID from the bundle.
func (b *Bundle) RemoveJWTKey(keyID string) {
	panic("not implemented")
}

// Marshal marshals the JWT bundle into a standard RFC 7517 JWKS document. The
// JWKS does not contain any SPIFFE-specific parameters.
func (b *Bundle) Marshal() ([]byte, error) {
	panic("not implemented")
}

// GetJWTBundleForTrustDomain returns the JWT bundle of the given trust domain.
// It implements the Source interface. It will fail if called with a trust
// domain other than the one the bundle belongs to.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	panic("not implemented")
}
