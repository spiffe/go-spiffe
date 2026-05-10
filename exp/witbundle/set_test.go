package witbundle_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/exp/witbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/require"
)

var (
	b1  = witbundle.New(td)
	td2 = spiffeid.RequireTrustDomainFromString("example-2.org")
)

func TestNewSet(t *testing.T) {
	s := witbundle.NewSet(b1)
	require.True(t, s.Has(td))

	s = witbundle.NewSet(witbundle.New(td), witbundle.New(td2))
	require.True(t, s.Has(td))
	require.True(t, s.Has(td2))
}

func TestAdd(t *testing.T) {
	s := witbundle.NewSet()
	require.False(t, s.Has(td))
	s.Add(b1)
	require.True(t, s.Has(td))
}

func TestRemove(t *testing.T) {
	s := witbundle.NewSet(b1)
	require.True(t, s.Has(td))
	s.Remove(td2)
	require.True(t, s.Has(td))
	s.Remove(td)
	require.False(t, s.Has(td))
}

func TestHas(t *testing.T) {
	s := witbundle.NewSet(witbundle.New(td))
	require.False(t, s.Has(td2))
	require.True(t, s.Has(td))
}

func TestSetGetWITBundleForTrustDomain(t *testing.T) {
	s := witbundle.NewSet(b1)
	_, err := s.GetWITBundleForTrustDomain(td2)
	require.EqualError(t, err, `witbundle: no WIT bundle for trust domain "example-2.org"`)

	b, err := s.GetWITBundleForTrustDomain(td)
	require.NoError(t, err)
	require.Equal(t, b1, b)
}
