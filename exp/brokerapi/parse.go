package brokerapi

import (
	"errors"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func parseX509Context(response *brokerpb.SubscribeToX509SVIDResponse) ([]*x509svid.SVID, *x509bundle.Set, error) {
	svids, err := parseX509SVIDs(response)
	if err != nil {
		return nil, nil, err
	}

	bundles, err := parseX509SVIDBundles(response)
	if err != nil {
		return nil, nil, err
	}

	return svids, bundles, nil
}

func parseX509SVIDs(response *brokerpb.SubscribeToX509SVIDResponse) ([]*x509svid.SVID, error) {
	if len(response.Svids) == 0 {
		return nil, errors.New("no X.509-SVIDs in response")
	}

	hints := make(map[string]struct{}, len(response.Svids))
	svids := make([]*x509svid.SVID, 0, len(response.Svids))
	for _, pbSVID := range response.Svids {
		// In the event of more than one X509SVID message with the same hint
		// value set, the first message in the list SHOULD be selected.
		if _, ok := hints[pbSVID.Hint]; ok && pbSVID.Hint != "" {
			continue
		}
		hints[pbSVID.Hint] = struct{}{}

		svid, err := x509svid.ParseRaw(pbSVID.X509Svid, pbSVID.X509SvidKey)
		if err != nil {
			return nil, err
		}
		svid.Hint = pbSVID.Hint
		svids = append(svids, svid)
	}

	return svids, nil
}

func parseX509SVIDBundles(response *brokerpb.SubscribeToX509SVIDResponse) (*x509bundle.Set, error) {
	bundles := make([]*x509bundle.Bundle, 0, len(response.Svids)+len(response.FederatedBundles))
	for _, pbSVID := range response.Svids {
		bundle, err := parseX509Bundle(pbSVID.SpiffeId, pbSVID.Bundle)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}

	for trustDomain, bundleBytes := range response.FederatedBundles {
		bundle, err := parseX509Bundle(trustDomain, bundleBytes)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}

	return x509bundle.NewSet(bundles...), nil
}

func parseX509Bundles(response *brokerpb.SubscribeToX509BundlesResponse) (*x509bundle.Set, error) {
	bundles := make([]*x509bundle.Bundle, 0, len(response.Bundles))
	for trustDomain, bundleBytes := range response.Bundles {
		bundle, err := parseX509Bundle(trustDomain, bundleBytes)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return x509bundle.NewSet(bundles...), nil
}

func parseX509Bundle(idOrName string, bundleBytes []byte) (*x509bundle.Bundle, error) {
	trustDomain, err := spiffeid.TrustDomainFromString(idOrName)
	if err != nil {
		return nil, err
	}
	return x509bundle.ParseRaw(trustDomain, bundleBytes)
}

func parseJWTSVIDs(response *brokerpb.FetchJWTSVIDResponse, audience []string) ([]*jwtsvid.SVID, error) {
	if len(response.Svids) == 0 {
		return nil, errors.New("no JWT-SVIDs in response")
	}

	hints := make(map[string]struct{}, len(response.Svids))
	svids := make([]*jwtsvid.SVID, 0, len(response.Svids))
	for _, pbSVID := range response.Svids {
		// In the event of more than one JWTSVID message with the same hint
		// value set, the first message in the list SHOULD be selected.
		if _, ok := hints[pbSVID.Hint]; ok && pbSVID.Hint != "" {
			continue
		}
		hints[pbSVID.Hint] = struct{}{}

		svid, err := jwtsvid.ParseInsecure(pbSVID.Svid, audience)
		if err != nil {
			return nil, err
		}
		svid.Hint = pbSVID.Hint
		svids = append(svids, svid)
	}

	return svids, nil
}

func parseJWTBundles(response *brokerpb.SubscribeToJWTBundlesResponse) (*jwtbundle.Set, error) {
	bundles := make([]*jwtbundle.Bundle, 0, len(response.Bundles))
	for trustDomain, bundleBytes := range response.Bundles {
		td, err := spiffeid.TrustDomainFromString(trustDomain)
		if err != nil {
			return nil, err
		}

		bundle, err := jwtbundle.Parse(td, bundleBytes)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}
	return jwtbundle.NewSet(bundles...), nil
}

func jwtAudience(params jwtsvid.Params) ([]string, error) {
	if params.Audience == "" {
		return nil, errors.New("audience is required")
	}
	return append([]string{params.Audience}, params.ExtraAudiences...), nil
}
