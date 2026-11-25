package brokerapi

import (
	"crypto/x509"
	"testing"

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
