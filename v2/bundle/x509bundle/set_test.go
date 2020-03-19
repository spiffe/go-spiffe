package x509bundle_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	td1 = spiffeid.RequireTrustDomainFromString("example-1.org")
	b1  = x509bundle.New(td1)
	td2 = spiffeid.RequireTrustDomainFromString("example-2.org")
	b2  = x509bundle.New(td2)
)

func TestNewSet(t *testing.T) {
	s := x509bundle.NewSet(b1)
	require.True(t, s.Has(td1))

	s = x509bundle.NewSet(b1, b2)
	require.True(t, s.Has(td1))
	require.True(t, s.Has(td2))
}

func TestAdd(t *testing.T) {
	s := x509bundle.NewSet()
	require.False(t, s.Has(td1))
	s.Add(b1)
	require.True(t, s.Has(td1))
}

func TestRemove(t *testing.T) {
	s := x509bundle.NewSet(b1)
	require.True(t, s.Has(td1))
	s.Remove(td2)
	require.True(t, s.Has(td1))
	s.Remove(td1)
	require.False(t, s.Has(td1))
}

func TestHas(t *testing.T) {
	s := x509bundle.NewSet(b1)
	require.False(t, s.Has(td2))
	require.True(t, s.Has(td1))
}

func TestSetGetX509BundleForTrustDomain(t *testing.T) {
	s := x509bundle.NewSet(b1)
	_, err := s.GetX509BundleForTrustDomain(td2)
	require.EqualError(t, err, `x509bundle: no X.509 bundle for trust domain "example-2.org"`)

	b, err := s.GetX509BundleForTrustDomain(td1)
	require.NoError(t, err)
	require.Equal(t, b1, b)
}
