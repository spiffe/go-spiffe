package jwtbundle

import (
	"crypto"
	"encoding/json"
	"io"
	"io/ioutil"
	"sync"

	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
)

var (
	jwtbundleErr = errs.Class("jwtbundle")
)

// Bundle is a collection of trusted JWT authorities for a trust domain.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx            sync.RWMutex
	jwtAuthorities map[string]crypto.PublicKey
}

// New creates a new bundle.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		jwtAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromJWTAuthorities creates a new bundle from JWT authorities
func FromJWTAuthorities(trustDomain spiffeid.TrustDomain, jwtAuthorities map[string]crypto.PublicKey) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		jwtAuthorities: jwtutil.CopyJWTAuthorities(jwtAuthorities),
	}
}

// Load loads a bundle from a file on disk.
func Load(trustDomain spiffeid.TrustDomain, path string) (*Bundle, error) {
	bundleBytes, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, jwtbundleErr.New("unable to read JWT bundle: %w", err)
	}

	return Parse(trustDomain, bundleBytes)
}

// Read decodes a bundle from a reader.
func Read(trustDomain spiffeid.TrustDomain, r io.Reader) (*Bundle, error) {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, jwtbundleErr.New("unable to read: %v", err)
	}

	return Parse(trustDomain, b)
}

// Parse parses a bundle from bytes.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	jwks := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(bundleBytes, jwks); err != nil {
		return nil, jwtbundleErr.New("unable to parse JWKS: %v", err)
	}

	bundle := New(trustDomain)
	for i, key := range jwks.Keys {
		if err := bundle.AddJWTAuthority(key.KeyID, key.Key); err != nil {
			return nil, jwtbundleErr.New("error adding authority %d of JWKS: %v", i, errs.Unwrap(err))
		}
	}

	return bundle, nil
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// JWTAuthorities returns the JWT authorities in the bundle, keyed by authority ID.
func (b *Bundle) JWTAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTAuthorities(b.jwtAuthorities)
}

// FindJWTAuthorities finds the JWT authority with the given authority id from the bundle. If the authority
// is found, it is returned and the boolean is true. Otherwise, the returned
// value is nil and the boolean is false.
func (b *Bundle) FindJWTAuthorities(authorityID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if jwtAuthority, ok := b.jwtAuthorities[authorityID]; ok {
		return jwtAuthority, true
	}
	return nil, false
}

// HasJWTAuthority returns true if the bundle has a JWT authority with the given authority id.
func (b *Bundle) HasJWTAuthority(authorityID string) bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	_, ok := b.jwtAuthorities[authorityID]
	return ok
}

// AddJWTAuthority adds a JWT authority to the bundle. If a JWT authority already exists
// under the given authority ID, it is replaced. A authority ID must be specified.
func (b *Bundle) AddJWTAuthority(authorityID string, jwtAuthority crypto.PublicKey) error {
	if authorityID == "" {
		return jwtbundleErr.New("authorityID cannot be empty")
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtAuthorities[authorityID] = jwtAuthority
	return nil
}

// RemoveJWTAuthority removes the JWT authority identified by the authority ID from the bundle.
func (b *Bundle) RemoveJWTAuthority(authorityID string) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	delete(b.jwtAuthorities, authorityID)
}

// SetJWTAuthorities sets the JWT authorities in the bundle.
func (b *Bundle) SetJWTAuthorities(jwtAuthorities map[string]crypto.PublicKey) {
	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtAuthorities = jwtutil.CopyJWTAuthorities(jwtAuthorities)
}

// Empty returns true if the bundle has no JWT authorities.
func (b *Bundle) Empty() bool {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return len(b.jwtAuthorities) == 0
}

// Marshal marshals the JWT bundle into a standard RFC 7517 JWKS document. The
// JWKS does not contain any SPIFFE-specific parameters.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	jwks := jose.JSONWebKeySet{}
	for authorityID, jwtAuthority := range b.jwtAuthorities {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtAuthority,
			KeyID: authorityID,
		})
	}

	return json.Marshal(jwks)
}

// GetJWTBundleForTrustDomain returns the JWT bundle for the given trust
// domain. It implements the Source interface. An error will be returned if
// the trust domain does not match that of the bundle.
func (b *Bundle) GetJWTBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, jwtbundleErr.New("no JWT bundle for trust domain %q", trustDomain)
	}

	return b, nil
}
