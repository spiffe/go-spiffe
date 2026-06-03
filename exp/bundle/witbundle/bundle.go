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
	witAuthorities map[string]crypto.PublicKey
}

// New creates a new empty bundle for the given trust domain.
func New(trustDomain spiffeid.TrustDomain) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		witAuthorities: make(map[string]crypto.PublicKey),
	}
}

// FromWITAuthorities creates a new bundle from a map of WIT authorities keyed
// by key ID.
func FromWITAuthorities(trustDomain spiffeid.TrustDomain, witAuthorities map[string]crypto.PublicKey) *Bundle {
	return &Bundle{
		trustDomain:    trustDomain,
		witAuthorities: jwtutil.CopyJWTAuthorities(witAuthorities),
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
		if err := bundle.AddWITAuthority(key.KeyID, key.Key); err != nil {
			return nil, wrapErr(fmt.Errorf("error adding authority %d of JWKS: %v", i, errors.Unwrap(err)))
		}
	}

	return bundle, nil
}

// TrustDomain returns the trust domain that the bundle belongs to.
func (b *Bundle) TrustDomain() spiffeid.TrustDomain {
	return b.trustDomain
}

// WITAuthorities returns the WIT authorities in the bundle, keyed by key ID.
func (b *Bundle) WITAuthorities() map[string]crypto.PublicKey {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	return jwtutil.CopyJWTAuthorities(b.witAuthorities)
}

// FindWITAuthority finds the WIT authority with the given key ID from the bundle.
// If the authority is found, it is returned and the boolean is true. Otherwise,
// the returned value is nil and the boolean is false.
func (b *Bundle) FindWITAuthority(keyID string) (crypto.PublicKey, bool) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	if witAuthority, ok := b.witAuthorities[keyID]; ok {
		return witAuthority, true
	}
	return nil, false
}

// AddWITAuthority adds a WIT authority to the bundle. If a WIT authority already
// exists under the given key ID, it is replaced. A key ID must be specified.
func (b *Bundle) AddWITAuthority(keyID string, witAuthority crypto.PublicKey) error {
	if keyID == "" {
		return wrapErr(errors.New("keyID cannot be empty"))
	}

	b.mtx.Lock()
	defer b.mtx.Unlock()

	b.witAuthorities[keyID] = witAuthority
	return nil
}

// Marshal marshals the WIT bundle into a standard RFC 7517 JWKS document.
func (b *Bundle) Marshal() ([]byte, error) {
	b.mtx.RLock()
	defer b.mtx.RUnlock()

	jwks := jose.JSONWebKeySet{}
	for keyID, witAuthority := range b.witAuthorities {
		jwks.Keys = append(jwks.Keys, jose.JSONWebKey{
			Key:   witAuthority,
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
