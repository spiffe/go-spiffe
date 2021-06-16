package spiffeid_test

import (
	"testing"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/stretchr/testify/assert"
)

var (
	zero = spiffeid.ID{}
	foo  = spiffeid.RequireFromString("spiffe://foo.test")
	fooA = spiffeid.RequireFromString("spiffe://foo.test/A")
	fooB = spiffeid.RequireFromString("spiffe://foo.test/B")
	fooC = spiffeid.RequireFromString("spiffe://foo.test/sub/C")
	barA = spiffeid.RequireFromString("spiffe://bar.test/A")
)

func TestMatchAny(t *testing.T) {
	testMatch(t, spiffeid.MatchAny(),
		"",
		"",
		"",
		"",
		"",
		"",
	)
}

func TestMatchID_AgainstIDWithPath(t *testing.T) {
	testMatch(t, spiffeid.MatchID(fooA),
		`unexpected ID ""`,
		`unexpected ID "spiffe://foo.test"`,
		``,
		`unexpected ID "spiffe://foo.test/B"`,
		`unexpected ID "spiffe://foo.test/sub/C"`,
		`unexpected ID "spiffe://bar.test/A"`,
	)
}

func TestMatchID_AgainstIDWithoutPath(t *testing.T) {
	testMatch(t, spiffeid.MatchID(foo),
		`unexpected ID ""`,
		``,
		`unexpected ID "spiffe://foo.test/A"`,
		`unexpected ID "spiffe://foo.test/B"`,
		`unexpected ID "spiffe://foo.test/sub/C"`,
		`unexpected ID "spiffe://bar.test/A"`,
	)
}

func TestMatchOneOf_OnAListOfIDs(t *testing.T) {
	testMatch(t, spiffeid.MatchOneOf(foo, fooB, fooC, barA),
		`unexpected ID ""`,
		``,
		`unexpected ID "spiffe://foo.test/A"`,
		``,
		``,
		``,
	)
}

func TestMatchOneOf_OnAnEmptyListOfIDs(t *testing.T) {
	testMatch(t, spiffeid.MatchOneOf(),
		`unexpected ID ""`,
		`unexpected ID "spiffe://foo.test"`,
		`unexpected ID "spiffe://foo.test/A"`,
		`unexpected ID "spiffe://foo.test/B"`,
		`unexpected ID "spiffe://foo.test/sub/C"`,
		`unexpected ID "spiffe://bar.test/A"`,
	)
}

func TestMatchMemberOf_AgainstNonEmptyTrustDomain(t *testing.T) {
	testMatch(t, spiffeid.MatchMemberOf(foo.TrustDomain()),
		`unexpected trust domain ""`,
		``,
		``,
		``,
		``,
		`unexpected trust domain "bar.test"`,
	)
}

func TestMatchMemberOf_AgainstEmptyTrustDomain(t *testing.T) {
	testMatch(t, spiffeid.MatchMemberOf(spiffeid.TrustDomain{}),
		``,
		`unexpected trust domain "foo.test"`,
		`unexpected trust domain "foo.test"`,
		`unexpected trust domain "foo.test"`,
		`unexpected trust domain "foo.test"`,
		`unexpected trust domain "bar.test"`,
	)
}

func testMatch(t *testing.T, matcher spiffeid.Matcher, zeroErr, fooErr, fooAErr, fooBErr, fooCErr, barAErr string) {
	test := func(id spiffeid.ID, expectErr string, msgAndArgs ...interface{}) {
		err := matcher(id)
		if expectErr != "" {
			assert.EqualError(t, err, expectErr, msgAndArgs...)
		} else {
			assert.NoError(t, err, msgAndArgs...)
		}
	}

	test(zero, zeroErr, "unexpected result for zero ID")
	test(foo, fooErr, "unexpected result for foo ID")
	test(fooA, fooAErr, "unexpected result for fooA ID")
	test(fooB, fooBErr, "unexpected result for fooB ID")
	test(fooC, fooCErr, "unexpected result for fooC ID")
	test(barA, barAErr, "unexpected result for fooD ID")
}
