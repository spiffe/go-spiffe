package brokerapi

import (
	"errors"
	"fmt"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	brokerpb "github.com/spiffe/go-spiffe/v2/exp/proto/spiffe/broker"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/jwtsvid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

func parseX509Context(response *brokerpb.SubscribeToX509SVIDResponse) ([]*x509svid.SVID, *x509bundle.Set, error) {
	pbSVIDs := uniqueX509SVIDs(response.Svids)
	if len(pbSVIDs) == 0 {
		return nil, nil, errors.New("no X.509-SVIDs in response")
	}

	svids, err := parseX509SVIDsFromProto(pbSVIDs)
	if err != nil {
		return nil, nil, err
	}

	bundles, err := parseX509SVIDBundles(pbSVIDs, response.FederatedBundles)
	if err != nil {
		return nil, nil, err
	}

	return svids, bundles, nil
}

func parseX509SVIDs(response *brokerpb.SubscribeToX509SVIDResponse) ([]*x509svid.SVID, error) {
	pbSVIDs := uniqueX509SVIDs(response.Svids)
	if len(pbSVIDs) == 0 {
		return nil, errors.New("no X.509-SVIDs in response")
	}
	return parseX509SVIDsFromProto(pbSVIDs)
}

func uniqueX509SVIDs(pbSVIDs []*brokerpb.X509SVID) []*brokerpb.X509SVID {
	hints := make(map[string]struct{}, len(pbSVIDs))
	unique := make([]*brokerpb.X509SVID, 0, len(pbSVIDs))
	for _, pbSVID := range pbSVIDs {
		if pbSVID == nil {
			unique = append(unique, nil)
			continue
		}
		// In the event of more than one X509SVID message with the same hint
		// value set, the first message in the list SHOULD be selected.
		if pbSVID.Hint != "" {
			if _, ok := hints[pbSVID.Hint]; ok {
				continue
			}
			hints[pbSVID.Hint] = struct{}{}
		}
		unique = append(unique, pbSVID)
	}
	return unique
}

func parseX509SVIDsFromProto(pbSVIDs []*brokerpb.X509SVID) ([]*x509svid.SVID, error) {
	svids := make([]*x509svid.SVID, 0, len(pbSVIDs))
	for _, pbSVID := range pbSVIDs {
		if pbSVID == nil {
			return nil, errors.New("X.509-SVID is required")
		}
		if pbSVID.SpiffeId == "" {
			return nil, errors.New("X.509-SVID SPIFFE ID is required")
		}
		expectedID, err := spiffeid.FromString(pbSVID.SpiffeId)
		if err != nil {
			return nil, fmt.Errorf("invalid X.509-SVID SPIFFE ID: %w", err)
		}
		if len(pbSVID.X509Svid) == 0 {
			return nil, errors.New("X.509-SVID certificate chain is required")
		}
		if len(pbSVID.X509SvidKey) == 0 {
			return nil, errors.New("X.509-SVID private key is required")
		}

		svid, err := x509svid.ParseRaw(pbSVID.X509Svid, pbSVID.X509SvidKey)
		if err != nil {
			return nil, err
		}
		if svid.ID != expectedID {
			return nil, fmt.Errorf("X.509-SVID SPIFFE ID %q does not match certificate SPIFFE ID %q", expectedID, svid.ID)
		}
		svid.Hint = pbSVID.Hint
		svids = append(svids, svid)
	}
	return svids, nil
}

func parseX509SVIDBundles(pbSVIDs []*brokerpb.X509SVID, federatedBundles map[string][]byte) (*x509bundle.Set, error) {
	bundles := make([]*x509bundle.Bundle, 0, len(pbSVIDs)+len(federatedBundles))
	for _, pbSVID := range pbSVIDs {
		if pbSVID == nil {
			return nil, errors.New("X.509-SVID is required")
		}
		bundle, err := parseX509Bundle(pbSVID.SpiffeId, pbSVID.Bundle)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}

	for trustDomain, bundleBytes := range federatedBundles {
		bundle, err := parseX509Bundle(trustDomain, bundleBytes)
		if err != nil {
			return nil, err
		}
		bundles = append(bundles, bundle)
	}

	return x509bundle.NewSet(bundles...), nil
}

func parseX509Bundles(response *brokerpb.SubscribeToX509BundlesResponse) (*x509bundle.Set, error) {
	if len(response.Bundles) == 0 {
		return nil, errors.New("no X.509 bundles in response")
	}

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
	if len(bundleBytes) == 0 {
		return nil, errors.New("X.509 bundle is required")
	}

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
		if pbSVID == nil {
			return nil, errors.New("JWT-SVID is required")
		}
		// In the event of more than one JWTSVID message with the same hint
		// value set, the first message in the list SHOULD be selected.
		if _, ok := hints[pbSVID.Hint]; ok && pbSVID.Hint != "" {
			continue
		}
		hints[pbSVID.Hint] = struct{}{}

		if pbSVID.SpiffeId == "" {
			return nil, errors.New("JWT-SVID SPIFFE ID is required")
		}
		expectedID, err := spiffeid.FromString(pbSVID.SpiffeId)
		if err != nil {
			return nil, fmt.Errorf("invalid JWT-SVID SPIFFE ID: %w", err)
		}
		if pbSVID.Svid == "" {
			return nil, errors.New("JWT-SVID is required")
		}

		svid, err := jwtsvid.ParseInsecure(pbSVID.Svid, audience)
		if err != nil {
			return nil, err
		}
		if svid.ID != expectedID {
			return nil, fmt.Errorf("JWT-SVID SPIFFE ID %q does not match token SPIFFE ID %q", expectedID, svid.ID)
		}
		svid.Hint = pbSVID.Hint
		svids = append(svids, svid)
	}

	return svids, nil
}

func parseJWTBundles(response *brokerpb.SubscribeToJWTBundlesResponse) (*jwtbundle.Set, error) {
	if len(response.Bundles) == 0 {
		return nil, errors.New("no JWT bundles in response")
	}

	bundles := make([]*jwtbundle.Bundle, 0, len(response.Bundles))
	for trustDomain, bundleBytes := range response.Bundles {
		td, err := spiffeid.TrustDomainFromString(trustDomain)
		if err != nil {
			return nil, err
		}
		if len(bundleBytes) == 0 {
			return nil, errors.New("JWT bundle is required")
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
