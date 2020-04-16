package spiffebundle

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"io"
	"io/ioutil"
	"sync"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
)

const (
	x509SVIDUse = "x509-svid"
	jwtSVIDUse  = "jwt-svid"
)

var (
	spiffebundleErr = errs.Class("spiffebundle")
)

type bundleDoc struct {
	jose.JSONWebKeySet
	SequenceNumber *uint64 `json:"spiffe_sequence,omitempty"`
	RefreshHint    *int64  `json:"spiffe_refresh_hint,omitempty"`
}

// Bundle is a collection of trusted public key material for a trust domain,
// conforming to the SPIFFE Bundle Format as part of the SPIFFE Trust Domain
// and Bundle specification:
// https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx            sync.RWMutex
	refreshHint    *time.Duration
	sequenceNumber *uint64
	jwtKeys        map[string]crypto.PublicKey
	x509Roots      []*x509.Certificate
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain: trustDomain,
		jwtKeys:     make(map[string]crypto.PublicKey),
	}
}

// Load loads a bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	bundleBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, spiffebundleErr.New("unable to read SPIFFE bundle: %w", err)
	}

	return Parse(trustDomain, bundleBytes)
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, spiffebundleErr.New("unable to read: %v", err)
	}

	return Parse(trustDomain, b)
}

// Parse parses a bundle from bytes.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	jwks := &bundleDoc{}
	if err := json.Unmarshal(bundleBytes, jwks); err != nil {
		return nil, spiffebundleErr.New("unable to parse JWKS: %v", err)
	}

	bundle := New(trustDomain)
	if jwks.RefreshHint != nil {
		bundle.SetRefreshHint(time.Second * time.Duration(*jwks.RefreshHint))
	}
	if jwks.SequenceNumber != nil {
		bundle.SetSequenceNumber(*jwks.SequenceNumber)
	}

	if jwks.Keys == nil {
		// The parameter keys MUST be present.
		// https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE_Trust_Domain_and_Bundle.md#413-keys
		return nil, spiffebundleErr.New("no keys found")
	}
	for i, key := range jwks.Keys {
		switch key.Use {
		// Two SVID types are supported: x509-svid and jwt-svid.
		case x509SVIDUse:
			if len(key.Certificates) != 1 {
				return nil, spiffebundleErr.New("expected a single certificate in %s entry %d; got %d", x509SVIDUse, i, len(key.Certificates))
			}
			bundle.AddX509Root(key.Certificates[0])
		case jwtSVIDUse:
			if err := bundle.AddJWTKey(key.KeyID, key.Key); err != nil {
				return nil, spiffebundleErr.New("error adding key %d of JWKS: %v", i, errs.Unwrap(err))
			}
		}
	}

	return bundle, nil
}

// FromX509Bundle creates a bundle from an X.509 bundle.
// The function panics in case of a nil X.509 bundle.
func FromX509Bundle(x509Bundle *x509bundle.Bundle) *Bundle {
	return &Bundle{
		trustDomain: x509Bundle.TrustDomain(),
		x509Roots:   x509Bundle.X509Roots(),
	}
}

// FromJWTBundle creates a bundle from a JWT bundle.
// The function panics in case of a nil JWT bundle.
func FromJWTBundle(jwtBundle *jwtbundle.Bundle) *Bundle {
	return &Bundle{
		trustDomain: jwtBundle.TrustDomain(),
		jwtKeys:     jwtBundle.JWTKeys(),
	}
}

// FromX509Roots creates a bundle from X.509 certificates.
func FromX509Roots(trustDomain spiffeid.TrustDomain, x509Roots []*x509.Certificate) *Bundle {
	return &Bundle{
		trustDomain: trustDomain,
		x509Roots:   x509util.CopyX509Roots(x509Roots),
	}
}

// FromJWTKeys creates a new bundle from JWT public keys.
func FromJWTKeys(trustDomain spiffeid.TrustDomain, jwtKeys map[string]crypto.PublicKey) *Bundle {
	return &Bundle{
		trustDomain: trustDomain,
		jwtKeys:     jwtutil.CopyJWTKeys(jwtKeys),
	}
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// X509Roots returns the X.509 roots in the bundle.
func (b *Bundle) X509Roots() []*x509.Certificate {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return x509util.CopyX509Roots(b.x509Roots)
}

// AddX509Root adds an X.509 root to the bundle. If the root already
// exists in the bundle, the contents of the bundle will remain unchanged.
func (b *Bundle) AddX509Root(x509Root *x509.Certificate) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	for _, r := range b.x509Roots {
		if r.Equal(x509Root) {
			return
		}
	}

	b.x509Roots = append(b.x509Roots, x509Root)
}

// RemoveX509Root removes an X.509 root from the bundle.
func (b *Bundle) RemoveX509Root(x509Root *x509.Certificate) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	for i, r := range b.x509Roots {
		if r.Equal(x509Root) {
			b.x509Roots = append(b.x509Roots[:i], b.x509Roots[i+1:]...)
			return
		}
	}
}

// HasX509Root checks if the given X.509 root exists in the bundle.
func (b *Bundle) HasX509Root(root *x509.Certificate) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	for _, r := range b.x509Roots {
		if r.Equal(root) {
			return true
		}
	}
	return false
}

// SetX509Roots sets the X.509 roots in the bundle.
func (b *Bundle) SetX509Roots(roots []*x509.Certificate) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.x509Roots = x509util.CopyX509Roots(roots)
}

// JWTKeys returns the JWT keys in the bundle, keyed by key ID.
func (b *Bundle) JWTKeys() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTKeys(b.jwtKeys)
}

// FindJWTKey finds the JWT key with the given key id from the bundle. If the key
// is found, it is returned and the boolean is true. Otherwise, the returned
// value is nil and the boolean is false.
func (b *Bundle) FindJWTKey(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	jwtKey, ok := b.jwtKeys[keyID]
	return jwtKey, ok
}

// HasJWTKey returns true if the bundle has a JWT key with the given key id.
func (b *Bundle) HasJWTKey(keyID string) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, ok := b.jwtKeys[keyID]
	return ok
}

// AddJWTKey adds a JWT key to the bundle. If a JWT key already exists
// under the given key ID, it is replaced. A key ID must be specified.
func (b *Bundle) AddJWTKey(keyID string, key crypto.PublicKey) error {
	if keyID == "" {
		return spiffebundleErr.New("keyID cannot be empty")
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtKeys[keyID] = key
	return nil
}

// RemoveJWTKey removes the JWT key identified by the key ID from the bundle.
func (b *Bundle) RemoveJWTKey(keyID string) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	delete(b.jwtKeys, keyID)
}

// SetJWTKeys sets the JWT keys in the bundle.
func (b *Bundle) SetJWTKeys(jwtKeys map[string]crypto.PublicKey) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtKeys = jwtutil.CopyJWTKeys(jwtKeys)
}

// Empty returns true if the bundle has no X.509 roots and no JWT keys.
func (b *Bundle) Empty() bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return len(b.x509Roots) == 0 && len(b.jwtKeys) == 0
}

// RefreshHint returns the refresh hint. If the refresh hint is set in
// the bundle, it is returned and the boolean is true. Otherwise, the returned
// value is zero and the boolean is false.
func (b *Bundle) RefreshHint() (refreshHint time.Duration, ok bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.refreshHint != nil {
		return *b.refreshHint, true
	}
	return 0, false
}

// SetRefreshHint sets the refresh hint. The refresh hint value will be
// truncated to time.Second.
func (b *Bundle) SetRefreshHint(refreshHint time.Duration) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refreshHint = &refreshHint
}

// ClearRefreshHint clears the refresh hint.
func (b *Bundle) ClearRefreshHint() {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.refreshHint = nil
}

// SequenceNumber returns the sequence number. If the sequence number is set in
// the bundle, it is returned and the boolean is true. Otherwise, the returned
// value is zero and the boolean is false.
func (b *Bundle) SequenceNumber() (uint64, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.sequenceNumber != nil {
		return *b.sequenceNumber, true
	}
	return 0, false
}

// SetSequenceNumber sets the sequence number.
func (b *Bundle) SetSequenceNumber(sequenceNumber uint64) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.sequenceNumber = &sequenceNumber
}

// ClearSequenceNumber clears the sequence number.
func (b *Bundle) ClearSequenceNumber() {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.sequenceNumber = nil
}

// Marshal marshals the bundle according to the SPIFFE Trust Domain and Bundle
// specification. The trust domain is not marshaled as part of the bundle and
// must be conveyed separately. See the specification for details.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	jwks := bundleDoc{}
	if b.refreshHint != nil {
		tr := int64((*b.refreshHint + (time.Second - 1)) / time.Second)
		jwks.RefreshHint = &tr
	}
	jwks.SequenceNumber = b.sequenceNumber
	for _, rootCA := range b.x509Roots {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:          rootCA.PublicKey,
			Certificates: []*x509.Certificate{rootCA},
			Use:          x509SVIDUse,
		})
	}

	for keyID, jwtKey := range b.jwtKeys {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtKey,
			KeyID: keyID,
			Use:   jwtSVIDUse,
		})
	}

	return json.Marshal(jwks)
}

// X509Bundle returns an X.509 bundle containing the X.509 roots in the SPIFFE
// bundle.
func (b *Bundle) X509Bundle() *x509bundle.Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	// FromX509Roots makes a copy, so we can pass our internal slice directly.
	return x509bundle.FromX509Roots(b.trustDomain, b.x509Roots)
}

// JWTBundle returns a JWT bundle containing the JWT keys in the SPIFFE bundle.
func (b *Bundle) JWTBundle() *jwtbundle.Bundle {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	// FromJWTBundle makes a copy, so we can pass our internal slice directly.
	return jwtbundle.FromJWTKeys(b.trustDomain, b.jwtKeys)
}

// GetBundleForTrustDomain returns the SPIFFE bundle for the given trust
// domain. It implements the Source interface. An error will be returned if the
// trust domain does not match that of the bundle.
func (b *Bundle) GetBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, spiffebundleErr.New("no SPIFFE bundle for trust domain %q", trustDomain)
	}

	return b, nil
}

// GetX509BundleForTrustDomain returns the X.509 bundle for the given trust
// domain. It implements the x509bundle.Source interface. An error will be
// returned if the trust domain does not match that of the bundle.
func (b *Bundle) GetX509BundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*x509bundle.Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, spiffebundleErr.New("no SPIFFE bundle for trust domain %q", trustDomain)
	}

	return b.X509Bundle(), nil
}

// GetJWTBundleForTrustDomain returns the JWT bundle of the given trust domain.
// It implements the jwtbundle.Source interface. An error will be returned if
// the trust domain does not match that of the bundle.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*jwtbundle.Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, spiffebundleErr.New("no SPIFFE bundle for trust domain %q", trustDomain)
	}

	return b.JWTBundle(), nil
}

func (b *Bundle) Equal(other *Bundle) bool {
	if b == nil || other == nil {
		return b == other
	}

	return b.trustDomain == other.trustDomain &&
		refreshHintEqual(b.refreshHint, other.refreshHint) &&
		sequenceNumberEqual(b.sequenceNumber, other.sequenceNumber) &&
		jwtutil.JWTKeysEqual(b.jwtKeys, other.jwtKeys) &&
		x509util.CertsEqual(b.x509Roots, other.x509Roots)
}

func refreshHintEqual(a, b *time.Duration) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}

func sequenceNumberEqual(a, b *uint64) bool {
	if a == nil || b == nil {
		return a == b
	}

	return *a == *b
}
