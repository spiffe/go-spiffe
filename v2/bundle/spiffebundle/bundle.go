package spiffebundle

import (
	"crypto"
	"crypto/x509"
	"io"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Bundle is a collection of trusted public key material for a trust domain,
// confirming to the SPIFFE Bundle Format as part of the SPIFFE Trust Domain
// and Bundle specification:
// https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md
type Bundle struct {
}

// New creates a new bundle
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

// FromX509Bundle creates a Bundle from an X.509 bundle.
func FromX509Bundle(x509Bundle *x509bundle.Bundle) *Bundle {
	panic("not implemented")
}

// FromJWTBundle creates a Bundle from a JWT bundle.
func FromJWTBundle(jwtBundle *jwtbundle.Bundle) *Bundle {
	panic("not implemented")
}

// TrustDomain returns the trust domain of the bundle.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	panic("not implemented")
}

// X509Roots returns the X.509 roots in the bundle.
func (b *Bundle) X509Roots() []*x509.Certificate {
	panic("not implemented")
}

// AddX509Root adds an X.509 root to the bundle. If the root already
// exists in the bundle, the contents of the bundle will remain unchanged.
func (b *Bundle) AddX509Root(*x509.Certificate) {
	panic("not implemented")
}

// RemoveX509Root removes an X.509 root to the bundle.
func (b *Bundle) RemoveX509Root(*x509.Certificate) {
	panic("not implemented")
}

// HasX509Root checks if the given X.509 root exists in the bundle
func (b *Bundle) HasX509Root(root *x509.Certificate) bool {
	panic("not implemented")
}

// JWTKeys returns the JWT keys in the bundle, keyed by key ID.
func (b *Bundle) JWTKeys() map[string]crypto.PublicKey {
	panic("not implemented")
}

// FindKey finds the JWT key with the given key id from the bundle. If the key
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

// RefreshHint returns the refresh hint. If the refresh hint is set in
// the bundle, it is returned and the boolean is true. Otherwise, the returned
// value is zero and the boolean is false.
func (b *Bundle) RefreshHint() (refreshHint time.Duration, ok bool) {
	panic("not implemented")
}

// SetRefreshHint sets the refresh hint. The refresh hint value will be
// truncated to time.Second.
func (b *Bundle) SetRefreshHint(refreshHint time.Duration) {
	panic("not implemented")
}

// ClearRefreshHint clears the refresh hint.
func (b *Bundle) ClearRefreshHint() {
	panic("not implemented")
}

// SequenceNumber returns the sequence number. If the sequence number is set in
// the bundle, it is returned and the boolean is true. Otherwise, the returned
// value is zero and the boolean is false.
func (b *Bundle) SequenceNumber() (uint64, bool) {
	panic("not implemented")
}

// SetSequenceNumber sets the sequence number.
func (b *Bundle) SetSequenceNumber(sequenceNumber uint64) {
	panic("not implemented")
}

// ClearSequenceNumber clears the sequence number.
func (b *Bundle) ClearSequenceNumber() {
	panic("not implemented")
}

// Marshal marshals the bundle according to the SPIFFE Trust Domain and Bundle
// specification. The trust domain is not marshaled as part of the bundle and
// must be conveyed separately. See the specification for details.
func (b *Bundle) Marshal() ([]byte, error) {
	panic("not implemented")
}

// X509Bundle returns an X.509 bundle containing the X.509 roots in the SPIFFE
// bundle.
func (b *Bundle) X509Bundle() *x509bundle.Bundle {
	panic("not implemented")
}

// JWTBundle returns a JWT bundle containing the JWT keys in the SPIFFE bundle.
func (b *Bundle) JWTBundle() *jwtbundle.Bundle {
	panic("not implemented")
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the Source interface. An error will be returned if the
// trust domain does not match that of the bundle.
func (b *Bundle) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	panic("not implemented")
}

// GetX509BundleForTrustDomain implements the x509bundle.Source interface. An
// error will be returned if the trust domain does not match that of the
// bundle.
func (b *Bundle) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	panic("not implemented")
}

// GetJWTBundleForTrustDomain implements the jwtbundle.Source interface. An
// error will be returned if the trust domain does not match that of the
// bundle.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	panic("not implemented")
}
