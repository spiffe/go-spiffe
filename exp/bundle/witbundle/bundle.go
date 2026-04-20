// Package witbundle provides support for WIT bundles, which are JWK Sets used
// to validate WIT-SVID signatures.
package witbundle

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"sync"

	"github.com/go-jose/go-jose/v4"
	"github.com/spiffe/go-spiffe/v2/internal/jwtutil"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// Bundle is a collection of trusted WIT authorities for a trust domain.
type Bundle struct {
	trustDomain spiffeid.TrustDomain

	mtx            sync.RWMutex
	jwtAuthorities map[string]crypto.PublicKey
}

// New creates a new empty bundle for the given trust domain.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		jwtAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromJWTAuthorities creates a new bundle from a map of JWT authorities keyed
// by key ID.
func FromJWTAuthorities(trustDomain spiffeid.TrustDomain, jwtAuthorities map[string]crypto.PublicKey) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		jwtAuthorities: jwtutil.CopyJWTAuthorities(jwtAuthorities),
	}
}

// Parse parses a bundle from a JWK Set JSON document.
func Parse(trustDomain spiffeid.TrustDomain, bundleBytes []byte) (*Bundle, error) {
	jwks := new(jose.JSONWebKeySet)
	if err := json.Unmarshal(bundleBytes, jwks); err != nil {
		return nil, wrapErr(fmt.Errorf("unable to parse JWKS: %v", err))
	}

	bundle := New(trustDomain)
	for i, key := range jwks.Keys {
		if err := bundle.AddJWTAuthority(key.KeyID, key.Key); err != nil {
			return nil, wrapErr(fmt.Errorf("error adding authority %d of JWKS: %v", i, errors.Unwrap(err)))
		}
	}

	return bundle, nil
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// JWTAuthorities returns the JWT authorities in the bundle, keyed by key ID.
func (b *Bundle) JWTAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTAuthorities(b.jwtAuthorities)
}

// FindJWTAuthority finds the JWT authority with the given key ID from the bundle.
// If the authority is found, it is returned and the boolean is true. Otherwise,
// the returned value is nil and the boolean is false.
func (b *Bundle) FindJWTAuthority(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if jwtAuthority, ok := b.jwtAuthorities[keyID]; ok {
		return jwtAuthority, true
	}
	return nil, false
}

// AddJWTAuthority adds a JWT authority to the bundle. If a JWT authority already
// exists under the given key ID, it is replaced. A key ID must be specified.
func (b *Bundle) AddJWTAuthority(keyID string, jwtAuthority crypto.PublicKey) error {
	if keyID == "" {
		return wrapErr(errors.New("keyID cannot be empty"))
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.jwtAuthorities[keyID] = jwtAuthority
	return nil
}

// Marshal marshals the WIT bundle into a standard RFC 7517 JWKS document.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	jwks := jose.JSONWebKeySet{}
	for keyID, jwtAuthority := range b.jwtAuthorities {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   jwtAuthority,
			KeyID: keyID,
		})
	}

	return json.Marshal(jwks)
}

// GetWITBundleForTrustDomain returns the WIT bundle for the given trust domain.
// It implements the Source interface. An error will be returned if the trust
// domain does not match that of the bundle.
func (b *Bundle) GetWITBundleForTrustDomain(trustDomain spiffeid.TrustDomain) (*Bundle, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if b.trustDomain != trustDomain {
		return nil, wrapErr(fmt.Errorf("no WIT bundle for trust domain %q", trustDomain))
	}

	return b, nil
}

func wrapErr(err error) error {
	return fmt.Errorf("witbundle: %w", err)
}
