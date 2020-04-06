package spiffebundle_test

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/spiffebundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	b1  = spiffebundle.New(td)
	td2 = spiffeid.RequireTrustDomainFromString("example-2.org")
)

func TestNewSet(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	require.True(t, s.Has(td))

	s = spiffebundle.NewSet(spiffebundle.New(td), spiffebundle.New(td2))
	require.True(t, s.Has(td))
	require.True(t, s.Has(td2))
}

func TestAdd(t *testing.T) {
	s := spiffebundle.NewSet()
	require.False(t, s.Has(td))
	s.Add(b1)
	require.True(t, s.Has(td))
}

func TestRemove(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	require.True(t, s.Has(td))
	s.Remove(td2)
	require.True(t, s.Has(td))
	s.Remove(td)
	require.False(t, s.Has(td))
}

func TestHas(t *testing.T) {
	s := spiffebundle.NewSet(spiffebundle.New(td))
	require.False(t, s.Has(td2))
	require.True(t, s.Has(td))
}

func TestSetGetBundleForTrustDomain(t *testing.T) {
	s := spiffebundle.NewSet(b1)
	_, err := s.GetBundleForTrustDomain(td2)
	require.EqualError(t, err, `spiffebundle: no SPIFFE bundle for trust domain "example-2.org"`)

	b, err := s.GetBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b1, b)
}

func TestSetGetX509BundleForTrustDomain(t *testing.T) {
	xb1 := x509bundle.FromX509Roots(td, []*x509.Certificate{x509Cert1})
	b := spiffebundle.FromX509Bundle(xb1)
	s := spiffebundle.NewSet(b)
	_, err := s.GetX509BundleForTrustDomain(td2)
	require.EqualError(t, err, `spiffebundle: no SPIFFE bundle for trust domain "example-2.org"`)

	xb2, err := s.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, xb1, xb2)
}

func TestSetGetJWTBundleForTrustDomain(t *testing.T) {
	jwtKeys := map[string]crypto.PublicKey{
		"key-1": "test-1",
		"key-2": "test-2",
	}
	jb1 := jwtbundle.FromJWTKeys(td, jwtKeys)
	b := spiffebundle.FromJWTBundle(jb1)
	s := spiffebundle.NewSet(b)
	_, err := s.GetJWTBundleForTrustDomain(td2)
	require.EqualError(t, err, `spiffebundle: no SPIFFE bundle for trust domain "example-2.org"`)

	jb2, err := s.GetJWTBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, jb1, jb2)
}
