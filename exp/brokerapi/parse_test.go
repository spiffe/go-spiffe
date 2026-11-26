package brokerapi

import (
	"crypto/x509"
	"testing"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/internal/test"
	"github.com/spiffe/go-spiffe/v2/internal/x509util"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

func TestParseX509SVIDs(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	svid2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/two"))
	svid3 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/three"))

	testCases := []struct {
		name    string
		hints   []string
		wantIDs []spiffeid.ID
	}{
		{
			name:    "duplicate hints keep the first SVID",
			hints:   []string{"hint", "hint", "other"},
			wantIDs: []spiffeid.ID{svid1.ID, svid3.ID},
		},
		{
			name:    "empty hints are not deduplicated",
			hints:   []string{"", ""},
			wantIDs: []spiffeid.ID{svid1.ID, svid2.ID},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			response := &brokerpb.SubscribeToX509SVIDResponse{}
			for i, svid := range []*x509svid.SVID{svid1, svid2, svid3}[:len(testCase.hints)] {
				pbSVID := makePBX509SVID(t, svid)
				pbSVID.Hint = testCase.hints[i]
				response.Svids = append(response.Svids, pbSVID)
			}

			svids, err := parseX509SVIDs(response)
			require.NoError(t, err)
			require.Equal(t, testCase.wantIDs, svidIDs(svids))
		})
	}
}

func TestParseX509SVIDsRequiresSVIDs(t *testing.T) {
	svids, err := parseX509SVIDs(&brokerpb.SubscribeToX509SVIDResponse{})
	require.EqualError(t, err, "no X.509-SVIDs in response")
	require.Nil(t, svids)
}

func TestParseJWTSVIDs(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	audience := []string{"audience"}
	svid1 := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/one"), audience)
	svid2 := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/two"), audience)
	svid3 := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/three"), audience)

	testCases := []struct {
		name    string
		hints   []string
		wantIDs []spiffeid.ID
	}{
		{
			name:    "duplicate hints keep the first SVID",
			hints:   []string{"hint", "hint", "other"},
			wantIDs: []spiffeid.ID{svid1.ID, svid3.ID},
		},
		{
			name:    "empty hints are not deduplicated",
			hints:   []string{"", ""},
			wantIDs: []spiffeid.ID{svid1.ID, svid2.ID},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			response := &brokerpb.FetchJWTSVIDResponse{}
			for i, svid := range []*jwtsvid.SVID{svid1, svid2, svid3}[:len(testCase.hints)] {
				response.Svids = append(response.Svids, &brokerpb.JWTSVID{
					SpiffeId: svid.ID.String(),
					Svid:     svid.Marshal(),
					Hint:     testCase.hints[i],
				})
			}

			svids, err := parseJWTSVIDs(response, audience)
			require.NoError(t, err)
			require.Equal(t, testCase.wantIDs, jwtSVIDIDs(svids))
		})
	}
}

func TestParseJWTSVIDsRequiresSVIDs(t *testing.T) {
	svids, err := parseJWTSVIDs(&brokerpb.FetchJWTSVIDResponse{}, []string{"audience"})
	require.EqualError(t, err, "no JWT-SVIDs in response")
	require.Nil(t, svids)
}

func TestParseX509ContextIgnoresDroppedSVIDBundles(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid1 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	svid2 := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/two"))

	pbSVID1 := makePBX509SVID(t, svid1)
	pbSVID1.Hint = "duplicate"
	pbSVID1.Bundle = x509util.ConcatRawCertsFromCerts(ca.X509Bundle().X509Authorities())

	pbSVID2 := makePBX509SVID(t, svid2)
	pbSVID2.Hint = "duplicate"
	pbSVID2.Bundle = []byte("invalid bundle")

	svids, bundles, err := parseX509Context(&brokerpb.SubscribeToX509SVIDResponse{
		Svids: []*brokerpb.X509SVID{pbSVID1, pbSVID2},
	})
	require.NoError(t, err)
	require.Equal(t, []spiffeid.ID{svid1.ID}, svidIDs(svids))
	requireX509BundleValue(t, bundles, td, ca.X509Bundle())
}

func TestParseX509ContextValidatesRequiredFields(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/one"))
	bundleBytes := x509util.ConcatRawCertsFromCerts(ca.X509Bundle().X509Authorities())

	testCases := []struct {
		name    string
		mutate  func(*brokerpb.X509SVID)
		wantErr string
	}{
		{
			name:    "missing SPIFFE ID",
			mutate:  func(pbSVID *brokerpb.X509SVID) { pbSVID.SpiffeId = "" },
			wantErr: "X.509-SVID SPIFFE ID is required",
		},
		{
			name:    "invalid SPIFFE ID",
			mutate:  func(pbSVID *brokerpb.X509SVID) { pbSVID.SpiffeId = "not-an-id" },
			wantErr: "invalid X.509-SVID SPIFFE ID",
		},
		{
			name:    "missing certificate chain",
			mutate:  func(pbSVID *brokerpb.X509SVID) { pbSVID.X509Svid = nil },
			wantErr: "X.509-SVID certificate chain is required",
		},
		{
			name:    "missing private key",
			mutate:  func(pbSVID *brokerpb.X509SVID) { pbSVID.X509SvidKey = nil },
			wantErr: "X.509-SVID private key is required",
		},
		{
			name:    "missing bundle",
			mutate:  func(pbSVID *brokerpb.X509SVID) { pbSVID.Bundle = nil },
			wantErr: "X.509 bundle is required",
		},
		{
			name: "mismatched SPIFFE ID",
			mutate: func(pbSVID *brokerpb.X509SVID) {
				pbSVID.SpiffeId = spiffeid.RequireFromPath(td, "/other").String()
			},
			wantErr: "does not match certificate SPIFFE ID",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pbSVID := makePBX509SVID(t, svid)
			pbSVID.Bundle = bundleBytes
			testCase.mutate(pbSVID)

			_, _, err := parseX509Context(&brokerpb.SubscribeToX509SVIDResponse{
				Svids: []*brokerpb.X509SVID{pbSVID},
			})
			require.ErrorContains(t, err, testCase.wantErr)
		})
	}
}

func TestParseX509BundlesValidatesRequiredFields(t *testing.T) {
	_, err := parseX509Bundles(&brokerpb.SubscribeToX509BundlesResponse{})
	require.EqualError(t, err, "no X.509 bundles in response")

	_, err = parseX509Bundles(&brokerpb.SubscribeToX509BundlesResponse{
		Bundles: map[string][]byte{"domain.test": nil},
	})
	require.EqualError(t, err, "X.509 bundle is required")
}

func TestParseJWTBundlesValidatesRequiredFields(t *testing.T) {
	_, err := parseJWTBundles(&brokerpb.SubscribeToJWTBundlesResponse{})
	require.EqualError(t, err, "no JWT bundles in response")

	_, err = parseJWTBundles(&brokerpb.SubscribeToJWTBundlesResponse{
		Bundles: map[string][]byte{"domain.test": nil},
	})
	require.EqualError(t, err, "JWT bundle is required")
}

func TestParseJWTSVIDsValidatesRequiredFields(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("domain.test")
	ca := test.NewCA(t, td)
	audience := []string{"audience"}
	svid := ca.CreateJWTSVID(spiffeid.RequireFromPath(td, "/one"), audience)

	testCases := []struct {
		name    string
		mutate  func(*brokerpb.JWTSVID)
		wantErr string
	}{
		{
			name:    "missing SPIFFE ID",
			mutate:  func(pbSVID *brokerpb.JWTSVID) { pbSVID.SpiffeId = "" },
			wantErr: "JWT-SVID SPIFFE ID is required",
		},
		{
			name:    "invalid SPIFFE ID",
			mutate:  func(pbSVID *brokerpb.JWTSVID) { pbSVID.SpiffeId = "not-an-id" },
			wantErr: "invalid JWT-SVID SPIFFE ID",
		},
		{
			name:    "missing token",
			mutate:  func(pbSVID *brokerpb.JWTSVID) { pbSVID.Svid = "" },
			wantErr: "JWT-SVID is required",
		},
		{
			name: "mismatched SPIFFE ID",
			mutate: func(pbSVID *brokerpb.JWTSVID) {
				pbSVID.SpiffeId = spiffeid.RequireFromPath(td, "/other").String()
			},
			wantErr: "does not match token SPIFFE ID",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			pbSVID := &brokerpb.JWTSVID{
				SpiffeId: svid.ID.String(),
				Svid:     svid.Marshal(),
			}
			testCase.mutate(pbSVID)

			_, err := parseJWTSVIDs(&brokerpb.FetchJWTSVIDResponse{
				Svids: []*brokerpb.JWTSVID{pbSVID},
			}, audience)
			require.ErrorContains(t, err, testCase.wantErr)
		})
	}
}

func requireX509BundleValue(t *testing.T, bundles *x509bundle.Set, trustDomain spiffeid.TrustDomain, expected *x509bundle.Bundle) {
	t.Helper()

	actual, err := bundles.GetX509BundleForTrustDomain(trustDomain)
	require.NoError(t, err)
	require.Equal(t, expected, actual)
}

func makePBX509SVID(t *testing.T, svid *x509svid.SVID) *brokerpb.X509SVID {
	t.Helper()

	keyBytes, err := x509.MarshalPKCS8PrivateKey(svid.PrivateKey)
	require.NoError(t, err)

	return &brokerpb.X509SVID{
		SpiffeId:    svid.ID.String(),
		X509Svid:    x509util.ConcatRawCertsFromCerts(svid.Certificates),
		X509SvidKey: keyBytes,
	}
}

func svidIDs(svids []*x509svid.SVID) []spiffeid.ID {
	ids := make([]spiffeid.ID, 0, len(svids))
	for _, svid := range svids {
		ids = append(ids, svid.ID)
	}
	return ids
}

func jwtSVIDIDs(svids []*jwtsvid.SVID) []spiffeid.ID {
	ids := make([]spiffeid.ID, 0, len(svids))
	for _, svid := range svids {
		ids = append(ids, svid.ID)
	}
	return ids
}
