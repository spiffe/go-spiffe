package spiffeid_test

import (
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTrustDomainFromString(t *testing.T) {
	assertOK := func(t *testing.T, in string, expected spiffeid.TrustDomain) {
		actual, err := spiffeid.TrustDomainFromString(in)
		if assert.NoError(t, err) {
			assert.Equal(t, expected, actual)
		}
		assert.NotPanics(t, func() {
			actual = spiffeid.RequireTrustDomainFromString(in)
			assert.Equal(t, expected, actual)
		})
	}

	assertFail := func(t *testing.T, in string, expectErr string) {
		td, err := spiffeid.TrustDomainFromString(in)
		assertErrorContains(t, err, expectErr)
		assert.Zero(t, td)
		assert.Panics(t, func() {
			spiffeid.RequireTrustDomainFromString(in)
		})
	}

	t.Run("reject empty", func(t *testing.T) {
		assertFail(t, "", `trust domain is missing`)
	})
	t.Run("allow id without path", func(t *testing.T) {
		assertOK(t, "spiffe://trustdomain", td)
	})
	t.Run("allow id with path", func(t *testing.T) {
		assertOK(t, "spiffe://trustdomain/path", td)
	})

	t.Run("reject bad ids", func(t *testing.T) {
		// We don't need to test all shapes of bad IDs, just a decent
		// representation across scheme, trust domain, and path.
		assertFail(t, "spiffe:/trustdomain/path", "scheme is missing or invalid")
		assertFail(t, "spiffe://", "trust domain is missing")
		assertFail(t, "spiffe:///path", "trust domain is missing")
		assertFail(t, "spiffe://trustdomain/", "path cannot have a trailing slash")
		assertFail(t, "spiffe://trustdomain/path/", "path cannot have a trailing slash")
		assertFail(t, "spiffe://%F0%9F%A4%AF/path", "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
		assertFail(t, "spiffe://trustdomain/%F0%9F%A4%AF", "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	})

	// Go all the way through 255, which ensures we reject UTF-8 appropriately
	for i := 0; i < 256; i++ {
		s := string(rune(i))
		suffix := fmt.Sprintf("%X", i)
		if _, ok := tdChars[s]; ok {
			t.Run("allow good trustdomain char "+suffix, func(t *testing.T) {
				expected := spiffeid.RequireTrustDomainFromString("trustdomain" + s)
				assertOK(t, "trustdomain"+s, expected)
				assertOK(t, "spiffe://trustdomain"+s, expected)
			})
		} else {
			t.Run("reject bad trustdomain char "+suffix, func(t *testing.T) {
				assertFail(t, "trustdomain"+s, "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
			})
		}
	}
}

func TestTrustDomainFromURI(t *testing.T) {
	parseURI := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)
		return u
	}
	assertOK := func(s string) {
		u := parseURI(s)
		td, err := spiffeid.TrustDomainFromURI(u)
		assert.NoError(t, err)
		assert.Equal(t, spiffeid.RequireTrustDomainFromString(u.Host), td)
	}
	assertFail := func(u *url.URL, expectErr string) {
		_, err := spiffeid.TrustDomainFromURI(u)
		assertErrorContains(t, err, expectErr)
	}

	assertOK("spiffe://trustdomain")
	assertOK("spiffe://trustdomain/path")

	assertFail(&url.URL{}, `cannot be empty`)
	assertFail(&url.URL{Scheme: "SPIFFE", Host: "trustdomain"}, `scheme is missing or invalid`)
	assertFail(parseURI("spiffe://trust$domain"), `trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores`)
	assertFail(parseURI("spiffe://trustdomain/path$"), `path segment characters are limited to letters, numbers, dots, dashes, and underscores`)
}

func TestTrustDomainID(t *testing.T) {
	assert.Zero(t, (spiffeid.TrustDomain{}).ID())

	expected := spiffeid.RequireFromString("spiffe://trustdomain")

	for _, s := range []string{"trustdomain", "spiffe://trustdomain", "spiffe://trustdomain/path"} {
		td = spiffeid.RequireTrustDomainFromString(s)
		assert.Equal(t, expected, td.ID())
	}
}

func TestTrustDomainIDString(t *testing.T) {
	assert.Empty(t, (spiffeid.TrustDomain{}).IDString())

	const expected = "spiffe://trustdomain"

	for _, s := range []string{"trustdomain", "spiffe://trustdomain", "spiffe://trustdomain/path"} {
		td = spiffeid.RequireTrustDomainFromString(s)
		assert.Equal(t, expected, td.IDString())
	}
}

func TestTrustDomainIsZero(t *testing.T) {
	assert.True(t, spiffeid.TrustDomain{}.IsZero())
	assert.False(t, spiffeid.RequireTrustDomainFromString("trustdomain").IsZero())
}

func TestTrustDomainCompare(t *testing.T) {
	a := spiffeid.RequireTrustDomainFromString("a")
	b := spiffeid.RequireTrustDomainFromString("b")
	assert.Equal(t, -1, a.Compare(b))
	assert.Equal(t, 0, a.Compare(a)) //nolint:gocritic // this comparison is intentional.
	assert.Equal(t, 1, b.Compare(a))
}

func TestTrustDomainTextMarshaler(t *testing.T) {
	var s struct {
		TrustDomain spiffeid.TrustDomain `json:"trustDomain"`
	}

	marshaled, err := json.Marshal(s)
	require.NoError(t, err)
	require.JSONEq(t, `{"trustDomain": ""}`, string(marshaled))

	s.TrustDomain = spiffeid.RequireTrustDomainFromString("trustdomain")

	marshaled, err = json.Marshal(s)
	require.NoError(t, err)
	require.JSONEq(t, `{"trustDomain": "trustdomain"}`, string(marshaled))
}

func TestTrustDomainTextUnmarshaler(t *testing.T) {
	var s struct {
		TrustDomain spiffeid.TrustDomain `json:"trustDomain"`
	}

	err := json.Unmarshal([]byte(`{"trustDomain": ""}`), &s)
	require.NoError(t, err)
	require.Zero(t, s.TrustDomain)

	err = json.Unmarshal([]byte(`{"trustDomain": "BAD"}`), &s)
	require.EqualError(t, err, "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
	require.Zero(t, s.TrustDomain)

	err = json.Unmarshal([]byte(`{"trustDomain": "trustdomain"}`), &s)
	require.NoError(t, err)
	require.Equal(t, "trustdomain", s.TrustDomain.String())
}
