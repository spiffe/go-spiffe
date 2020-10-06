package x509bundle_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/stretchr/testify/require"
)

var (
	b1 = x509bundle.New(td)
	b2 = x509bundle.New(td2)
)

func TestNewSet(t *testing.T) {
	s := x509bundle.NewSet(b1)
	require.True(t, s.Has(td))

	s = x509bundle.NewSet(b1, b2)
	require.True(t, s.Has(td))
	require.True(t, s.Has(td2))
}

func TestAdd(t *testing.T) {
	s := x509bundle.NewSet()
	require.False(t, s.Has(td))
	s.Add(b1)
	require.True(t, s.Has(td))
}

func TestRemove(t *testing.T) {
	s := x509bundle.NewSet(b1)
	require.True(t, s.Has(td))
	s.Remove(td2)
	require.True(t, s.Has(td))
	s.Remove(td)
	require.False(t, s.Has(td))
}

func TestHas(t *testing.T) {
	s := x509bundle.NewSet(b1)
	require.False(t, s.Has(td2))
	require.True(t, s.Has(td))
}

func TestSetGetX509BundleForTrustDomain(t *testing.T) {
	s := x509bundle.NewSet(b1)
	_, err := s.GetX509BundleForTrustDomain(td2)
	require.EqualError(t, err, `x509bundle: no X.509 bundle for trust domain "domain2.test"`)

	b, err := s.GetX509BundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b1, b)
}
