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

var (
	td = spiffeid.RequireTrustDomainFromString("trustdomain")

	lowerAlpha = asSet(
		"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m",
		"n", "o", "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z",
	)
	upperAlpha = asSet(
		"A", "B", "C", "D", "E", "F", "G", "H", "I", "J", "K", "L", "M",
		"N", "O", "P", "Q", "R", "S", "T", "U", "V", "W", "X", "Y", "Z",
	)

	numbers = asSet(
		"0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
	)

	special = asSet(
		".", "-", "_",
	)

	tdChars   = mergeSets(lowerAlpha, numbers, special)
	pathChars = mergeSets(lowerAlpha, upperAlpha, numbers, special)
)

func TestFromString(t *testing.T) {
	assertOK := func(t *testing.T, in string, expectTD spiffeid.TrustDomain, expectPath string) {
		id, err := spiffeid.FromString(in)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, expectTD, expectPath)
		}
		id, err = spiffeid.FromStringf("%s", in)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, expectTD, expectPath)
		}
		assert.NotPanics(t, func() {
			id = spiffeid.RequireFromString(in)
			assertIDEqual(t, id, expectTD, expectPath)
		})
		assert.NotPanics(t, func() {
			id = spiffeid.RequireFromStringf("%s", in)
			assertIDEqual(t, id, expectTD, expectPath)
		})
	}

	assertFail := func(t *testing.T, in string, expectErr string) {
		out, err := spiffeid.FromString(in)
		assertErrorContains(t, err, expectErr)
		assert.Zero(t, out)
		out, err = spiffeid.FromStringf("%s", in)
		assertErrorContains(t, err, expectErr)
		assert.Zero(t, out)
		assert.Panics(t, func() {
			spiffeid.RequireFromString(in)
		})
		assert.Panics(t, func() {
			spiffeid.RequireFromStringf("%s", in)
		})
	}

	t.Run("reject empty", func(t *testing.T) {
		assertFail(t, "", `cannot be empty`)
	})
	t.Run("path is optional", func(t *testing.T) {
		assertOK(t, "spiffe://trustdomain", td, "")
	})

	// Go all the way through 255, which ensures we reject UTF-8 appropriately
	for i := 0; i < 256; i++ {
		if i == '/' {
			// Don't test / since it is the delimeter between path segments
			continue
		}
		s := string(rune(i))
		suffix := fmt.Sprintf("%X", i)
		if _, ok := tdChars[s]; ok {
			t.Run("allow good trustdomain char "+suffix, func(t *testing.T) {
				assertOK(t, "spiffe://trustdomain"+s+"/path", spiffeid.RequireTrustDomainFromString("trustdomain"+s), "/path")
			})
		} else {
			t.Run("reject bad trustdomain char "+suffix, func(t *testing.T) {
				assertFail(t, "spiffe://trustdomain"+s+"/path", "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
			})
		}

		if _, ok := pathChars[s]; ok {
			t.Run("allow good path char "+suffix, func(t *testing.T) {
				assertOK(t, "spiffe://trustdomain/path"+s, td, "/path"+s)
			})
		} else {
			t.Run("reject bad path char "+suffix, func(t *testing.T) {
				assertFail(t, "spiffe://trustdomain/path"+s, "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
			})
		}
	}

	t.Run("reject bad scheme", func(t *testing.T) {
		assertFail(t, "s", "scheme is missing or invalid")
		assertFail(t, "spiffe:/", "scheme is missing or invalid")
		assertFail(t, "Spiffe://", "scheme is missing or invalid")
	})

	t.Run("reject missing trust domain", func(t *testing.T) {
		assertFail(t, "spiffe://", "trust domain is missing")
		assertFail(t, "spiffe:///", "trust domain is missing")
	})

	t.Run("reject empty segments", func(t *testing.T) {
		assertFail(t, "spiffe://trustdomain/", "path cannot have a trailing slash")
		assertFail(t, "spiffe://trustdomain//", "path cannot contain empty segments")
		assertFail(t, "spiffe://trustdomain//path", "path cannot contain empty segments")
		assertFail(t, "spiffe://trustdomain/path/", "path cannot have a trailing slash")
	})

	t.Run("reject dot segments", func(t *testing.T) {
		assertFail(t, "spiffe://trustdomain/.", "path cannot contain dot segments")
		assertFail(t, "spiffe://trustdomain/./path", "path cannot contain dot segments")
		assertFail(t, "spiffe://trustdomain/path/./other", "path cannot contain dot segments")
		assertFail(t, "spiffe://trustdomain/path/..", "path cannot contain dot segments")
		assertFail(t, "spiffe://trustdomain/..", "path cannot contain dot segments")
		assertFail(t, "spiffe://trustdomain/../path", "path cannot contain dot segments")
		assertFail(t, "spiffe://trustdomain/path/../other", "path cannot contain dot segments")
		// The following are ok since the the segments, while containing dots
		// are not all dots (or are more than two dots)
		assertOK(t, "spiffe://trustdomain/.path", td, "/.path")
		assertOK(t, "spiffe://trustdomain/..path", td, "/..path")
		assertOK(t, "spiffe://trustdomain/...", td, "/...")
	})

	t.Run("reject percent encoding", func(t *testing.T) {
		// percent-encoded unicode
		assertFail(t, "spiffe://%F0%9F%A4%AF/path", "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
		assertFail(t, "spiffe://trustdomain/%F0%9F%A4%AF", "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
		// percent-encoded ascii
		assertFail(t, "spiffe://%62%61%64/path", "trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores")
		assertFail(t, "spiffe://trustdomain/%62%61%64", "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	})
}

func TestFromURI(t *testing.T) {
	parseURI := func(s string) *url.URL {
		u, err := url.Parse(s)
		require.NoError(t, err)
		return u
	}
	assertOK := func(s string) {
		id, err := spiffeid.FromURI(parseURI(s))
		assert.NoError(t, err)
		assert.Equal(t, spiffeid.RequireFromString(s), id)
	}
	assertFail := func(u *url.URL, expectErr string) {
		id, err := spiffeid.FromURI(u)
		assertErrorContains(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK("spiffe://trustdomain")
	assertOK("spiffe://trustdomain/path")

	assertFail(&url.URL{}, `cannot be empty`)
	assertFail(&url.URL{Scheme: "SPIFFE", Host: "trustdomain"}, `scheme is missing or invalid`)
	assertFail(parseURI("spiffe://trust$domain"), `trust domain characters are limited to lowercase letters, numbers, dots, dashes, and underscores`)
	assertFail(parseURI("spiffe://trustdomain/path$"), `path segment characters are limited to letters, numbers, dots, dashes, and underscores`)
}

func TestFromSegments(t *testing.T) {
	assertOK := func(segments []string, expectPath string) {
		id, err := spiffeid.FromSegments(td, segments...)
		assert.NoError(t, err)
		assertIDEqual(t, id, td, expectPath)
	}
	assertFail := func(segments []string, expectErr string) {
		id, err := spiffeid.FromSegments(td, segments...)
		assertErrorContains(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK(nil, "")
	assertOK([]string{}, "")
	assertOK([]string{"foo"}, "/foo")
	assertOK([]string{"foo", "bar"}, "/foo/bar")

	assertFail([]string{""}, "path cannot contain empty segments")
	assertFail([]string{"/"}, "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertFail([]string{"/foo"}, "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
	assertFail([]string{"$"}, "path segment characters are limited to letters, numbers, dots, dashes, and underscores")
}

func TestFromPathf(t *testing.T) {
	id, err := spiffeid.FromPathf(td, "%s", "/foo")
	if assert.NoError(t, err) {
		assertIDEqual(t, id, td, "/foo")
	}

	id, err = spiffeid.FromPathf(td, "")
	if assert.NoError(t, err) {
		assertIDEqual(t, id, td, "")
	}

	id, err = spiffeid.FromPathf(td, "%s", "foo")
	if assert.EqualError(t, err, `path must have a leading slash`) {
		assert.Zero(t, id)
	}

	id, err = spiffeid.FromPathf(td, "/")
	if assert.EqualError(t, err, `path cannot have a trailing slash`) {
		assert.Zero(t, id)
	}
}

func TestIDMemberOf(t *testing.T) {
	// Common case
	id := spiffeid.RequireFromSegments(td, "path", "element")
	assert.True(t, id.MemberOf(td))

	// Empty path
	id = spiffeid.RequireFromSegments(td)
	assert.True(t, id.MemberOf(td))

	// Is not member of
	td2 := spiffeid.RequireTrustDomainFromString("domain2.test")
	id = spiffeid.RequireFromSegments(td2, "path", "element")
	assert.False(t, id.MemberOf(td))
}

func TestIDString(t *testing.T) {
	id := spiffeid.ID{}
	assert.Empty(t, id.String())

	id = spiffeid.RequireFromString("spiffe://trustdomain")
	assert.Equal(t, "spiffe://trustdomain", id.String())

	id = spiffeid.RequireFromString("spiffe://trustdomain/path")
	assert.Equal(t, "spiffe://trustdomain/path", id.String())
}

func TestIDURL(t *testing.T) {
	asURL := func(td, path string) *url.URL {
		return &url.URL{
			Scheme: "spiffe",
			Host:   td,
			Path:   path,
		}
	}

	// Common case
	id := spiffeid.RequireFromSegments(td, "path", "element")
	assert.Equal(t, asURL("trustdomain", "/path/element"), id.URL())

	// Empty path
	id = spiffeid.RequireFromSegments(td)
	assert.Equal(t, asURL("trustdomain", ""), id.URL())

	// Empty ID
	id = spiffeid.ID{}
	assert.Equal(t, &url.URL{}, id.URL())
}

func TestIDReplacePath(t *testing.T) {
	assertOK := func(startWith, replaceWith, expectPath string) {
		id, err := spiffeid.RequireFromPath(td, startWith).ReplacePath(replaceWith)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, td, expectPath)
		}
	}

	assertFail := func(startWith, replaceWith, expectErr string) {
		id, err := spiffeid.RequireFromPath(td, startWith).ReplacePath(replaceWith)
		assert.EqualError(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK("", "/foo", "/foo")
	assertOK("/path", "/foo", "/foo")

	assertFail("", "foo", `path must have a leading slash`)
	assertFail("/path", "/", `path cannot have a trailing slash`)
	assertFail("/path", "foo", `path must have a leading slash`)

	id, err := (spiffeid.ID{}).ReplacePath("/")
	assert.EqualError(t, err, "cannot replace path on a zero ID value")
	assert.Zero(t, id)
}

func TestIDReplacePathf(t *testing.T) {
	assertOK := func(startWith, replaceWith, expectPath string) {
		id, err := spiffeid.RequireFromPath(td, startWith).ReplacePathf("%s", replaceWith)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, td, expectPath)
		}
	}

	assertFail := func(startWith, replaceWith, expectErr string) {
		id, err := spiffeid.RequireFromPath(td, startWith).ReplacePathf("%s", replaceWith)
		assert.EqualError(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK("", "/foo", "/foo")
	assertOK("/path", "/foo", "/foo")

	assertFail("", "foo", `path must have a leading slash`)
	assertFail("/path", "/", `path cannot have a trailing slash`)
	assertFail("/path", "foo", `path must have a leading slash`)

	id, err := (spiffeid.ID{}).ReplacePathf("%s", "/")
	assert.EqualError(t, err, "cannot replace path on a zero ID value")
	assert.Zero(t, id)
}

func TestIDReplaceSegments(t *testing.T) {
	assertOK := func(startWith string, replaceWith []string, expectPath string) {
		id, err := spiffeid.RequireFromPath(td, startWith).ReplaceSegments(replaceWith...)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, td, expectPath)
		}
	}

	assertFail := func(startWith string, replaceWith []string, expectErr string) {
		id, err := spiffeid.RequireFromPath(td, startWith).ReplaceSegments(replaceWith...)
		assert.EqualError(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK("", []string{"foo"}, "/foo")
	assertOK("/path", []string{"foo"}, "/foo")

	assertFail("", []string{""}, `path cannot contain empty segments`)
	assertFail("", []string{"/foo"}, `path segment characters are limited to letters, numbers, dots, dashes, and underscores`)

	id, err := (spiffeid.ID{}).ReplaceSegments("/")
	assert.EqualError(t, err, "cannot replace path segments on a zero ID value")
	assert.Zero(t, id)
}

func TestIDAppendPath(t *testing.T) {
	assertOK := func(startWith, replaceWith, expectPath string) {
		id, err := spiffeid.RequireFromPath(td, startWith).AppendPath(replaceWith)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, td, expectPath)
		}
	}

	assertFail := func(startWith, replaceWith, expectErr string) {
		id, err := spiffeid.RequireFromPath(td, startWith).AppendPath(replaceWith)
		assert.EqualError(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK("", "/foo", "/foo")
	assertOK("/path", "/foo", "/path/foo")

	assertFail("", "foo", `path must have a leading slash`)
	assertFail("/path", "/", `path cannot have a trailing slash`)
	assertFail("/path", "foo", `path must have a leading slash`)

	id, err := (spiffeid.ID{}).AppendPath("/")
	assert.EqualError(t, err, "cannot append path on a zero ID value")
	assert.Zero(t, id)
}

func TestIDAppendPathf(t *testing.T) {
	assertOK := func(startWith, replaceWith, expectPath string) {
		id, err := spiffeid.RequireFromPath(td, startWith).AppendPathf("%s", replaceWith)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, td, expectPath)
		}
	}

	assertFail := func(startWith, replaceWith, expectErr string) {
		id, err := spiffeid.RequireFromPath(td, startWith).AppendPathf("%s", replaceWith)
		assert.EqualError(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK("", "/foo", "/foo")
	assertOK("/path", "/foo", "/path/foo")

	assertFail("", "foo", `path must have a leading slash`)
	assertFail("/path", "/", `path cannot have a trailing slash`)
	assertFail("/path", "foo", `path must have a leading slash`)

	id, err := (spiffeid.ID{}).AppendPathf("%s", "/")
	assert.EqualError(t, err, "cannot append path on a zero ID value")
	assert.Zero(t, id)
}

func TestIDAppendSegments(t *testing.T) {
	assertOK := func(startWith string, replaceWith []string, expectPath string) {
		id, err := spiffeid.RequireFromPath(td, startWith).AppendSegments(replaceWith...)
		if assert.NoError(t, err) {
			assertIDEqual(t, id, td, expectPath)
		}
	}

	assertFail := func(startWith string, replaceWith []string, expectErr string) {
		id, err := spiffeid.RequireFromPath(td, startWith).AppendSegments(replaceWith...)
		assert.EqualError(t, err, expectErr)
		assert.Zero(t, id)
	}

	assertOK("", []string{"foo"}, "/foo")
	assertOK("/path", []string{"foo"}, "/path/foo")

	assertFail("", []string{""}, `path cannot contain empty segments`)
	assertFail("", []string{"/foo"}, `path segment characters are limited to letters, numbers, dots, dashes, and underscores`)

	id, err := (spiffeid.ID{}).AppendSegments("/")
	assert.EqualError(t, err, "cannot append path segments on a zero ID value")
	assert.Zero(t, id)
}

func TestIDIsZero(t *testing.T) {
	assert.True(t, spiffeid.ID{}.IsZero())
	assert.False(t, td.ID().IsZero())
}

func TestIDTextMarshaler(t *testing.T) {
	var s struct {
		ID spiffeid.ID `json:"id"`
	}

	marshaled, err := json.Marshal(s)
	require.NoError(t, err)
	require.JSONEq(t, `{"id": ""}`, string(marshaled))

	s.ID = spiffeid.RequireFromString("spiffe://trustdomain/path")

	marshaled, err = json.Marshal(s)
	require.NoError(t, err)
	require.JSONEq(t, `{"id": "spiffe://trustdomain/path"}`, string(marshaled))
}

func TestIDTextUnmarshaler(t *testing.T) {
	var s struct {
		ID spiffeid.ID `json:"id"`
	}

	err := json.Unmarshal([]byte(`{"id": ""}`), &s)
	require.NoError(t, err)
	require.Zero(t, s.ID)

	err = json.Unmarshal([]byte(`{"id": "BAD"}`), &s)
	require.EqualError(t, err, "scheme is missing or invalid")
	require.Zero(t, s.ID)

	err = json.Unmarshal([]byte(`{"id": "spiffe://trustdomain/path"}`), &s)
	require.NoError(t, err)
	require.Equal(t, "spiffe://trustdomain/path", s.ID.String())
}

func BenchmarkIDFromString(b *testing.B) {
	s := "spiffe://trustdomain/path"
	for n := 0; n < b.N; n++ {
		escapes(spiffeid.RequireFromString(s).String())
	}
}

func BenchmarkIDFromPath(b *testing.B) {
	for n := 0; n < b.N; n++ {
		escapes(spiffeid.RequireFromPath(td, "/path").String())
	}
}

func BenchmarkIDFromPathf(b *testing.B) {
	for n := 0; n < b.N; n++ {
		escapes(spiffeid.RequireFromPathf(td, "%s", "/path").String())
	}
}

func BenchmarkIDFromSegments(b *testing.B) {
	for n := 0; n < b.N; n++ {
		escapes(spiffeid.RequireFromSegments(td, "path").String())
	}
}

func assertIDEqual(t *testing.T, id spiffeid.ID, expectTD spiffeid.TrustDomain, expectPath string) {
	assert.Equal(t, expectTD, id.TrustDomain(), "unexpected trust domain")
	assert.Equal(t, expectPath, id.Path(), "unexpected path")
	assert.Equal(t, id.String(), expectTD.IDString()+expectPath, "unexpected ID string")
	assert.Equal(t, id.URL().String(), id.String(), "unexpected URL representation")
}

func asSet(ss ...string) map[string]struct{} {
	set := make(map[string]struct{})
	for _, s := range ss {
		set[s] = struct{}{}
	}
	return set
}

func mergeSets(sets ...map[string]struct{}) map[string]struct{} {
	merged := make(map[string]struct{})
	for _, set := range sets {
		for k, v := range set {
			merged[k] = v
		}
	}
	return merged
}

func assertErrorContains(t *testing.T, err error, contains string) {
	if assert.Error(t, err) {
		assert.Contains(t, err.Error(), contains)
	}
}

var dummy struct {
	b bool
	x string
}

// escapes prevents a string from being stack allocated due to escape analysis
func escapes(s string) {
	if dummy.b {
		dummy.x = s
	}
}
