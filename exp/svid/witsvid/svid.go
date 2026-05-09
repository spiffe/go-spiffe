// Package witsvid provides support for WIT-SVIDs (Workload Identity Token SVIDs),
// an experimental SPIFFE credential type based on the IETF WIMSE WIT specification.
// WIT-SVIDs bind a public key to the workload identity via the cnf.jwk claim and
// require proof of possession — they are never bearer tokens.
package witsvid

import (
	"crypto"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

var allowedSignatureAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
}

// SVID represents a WIT-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the WIT-SVID as present in the 'sub' claim.
	ID spiffeid.ID

	// Expiry is the expiration time of the WIT-SVID as present in the 'exp' claim.
	Expiry time.Time

	// PublicKey is the public key bound to the WIT-SVID via the cnf.jwk claim.
	PublicKey crypto.PublicKey

	// KeyID is the key ID from the JOSE header.
	KeyID string

	// PrivateKey is the private key corresponding to PublicKey. It is populated
	// when the WIT-SVID is fetched from the Workload API, and nil otherwise.
	PrivateKey crypto.PrivateKey

	// Hint is an operator-specified string used to provide guidance on how this
	// identity should be used by a workload when more than one SVID is returned.
	Hint string

	// token is the serialized JWS compact serialization.
	token string
}

// Marshal returns the WIT-SVID as a JWS compact serialization string.
func (s *SVID) Marshal() string {
	return s.token
}

// ParseAndValidate parses and validates a WIT-SVID token, verifying its
// signature using the provided WIT bundle source.
func ParseAndValidate(token string, bundles witbundle.Source) (*SVID, error) {
	return parse(token, func(tok *jwt.JSONWebToken, trustDomain spiffeid.TrustDomain, keyID string) error {
		bundle, err := bundles.GetWITBundleForTrustDomain(trustDomain)
		if err != nil {
			return wrapErr(fmt.Errorf("no WIT bundle found for trust domain %q", trustDomain))
		}

		authority, ok := bundle.FindJWTAuthority(keyID)
		if !ok {
			return wrapErr(fmt.Errorf("no WIT authority %q found for trust domain %q", keyID, trustDomain))
		}

		// Verify signature by claiming with the authority key.
		var dummy map[string]interface{}
		if err := tok.Claims(authority, &dummy); err != nil {
			return wrapErr(fmt.Errorf("signature verification failed: %v", err))
		}
		return nil
	})
}

// ParseInsecure parses a WIT-SVID token without verifying its signature.
// This should only be used when the token was received from a trusted source
// (e.g., the Workload API).
func ParseInsecure(token string) (*SVID, error) {
	return parse(token, func(*jwt.JSONWebToken, spiffeid.TrustDomain, string) error {
		return nil
	})
}

type verifyFn func(*jwt.JSONWebToken, spiffeid.TrustDomain, string) error

func parse(token string, verify verifyFn) (*SVID, error) {
	tok, err := jwt.ParseSigned(token, allowedSignatureAlgorithms)
	if err != nil {
		return nil, wrapErr(errors.New("unable to parse WIT-SVID token"))
	}

	// Validate typ header: MUST be "wit+jwt"
	typ, _ := tok.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if typ != "wit+jwt" {
		return nil, wrapErr(fmt.Errorf("token header type must be %q, got %q", "wit+jwt", typ))
	}

	// kid header MUST be present
	keyID := tok.Headers[0].KeyID
	if keyID == "" {
		return nil, wrapErr(errors.New("token header missing key id"))
	}

	// Parse standard claims without verification
	var stdClaims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&stdClaims); err != nil {
		return nil, wrapErr(fmt.Errorf("unable to parse standard claims: %v", err))
	}

	if stdClaims.Subject == "" {
		return nil, wrapErr(errors.New("token missing subject claim"))
	}
	if stdClaims.Expiry == nil {
		return nil, wrapErr(errors.New("token missing exp claim"))
	}
	if len(stdClaims.Audience) > 0 {
		return nil, wrapErr(errors.New("WIT-SVID must not contain aud claim"))
	}

	spiffeID, err := spiffeid.FromString(stdClaims.Subject)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("token has an invalid subject claim: %v", err))
	}

	// Parse full claims map to extract cnf.jwk
	var rawClaims map[string]interface{}
	if err := tok.UnsafeClaimsWithoutVerification(&rawClaims); err != nil {
		return nil, wrapErr(fmt.Errorf("unable to parse claims: %v", err))
	}

	publicKey, err := extractCnfJWK(rawClaims)
	if err != nil {
		return nil, err
	}

	// Verify expiry
	if stdClaims.Expiry.Time().Before(time.Now()) {
		return nil, wrapErr(errors.New("token has expired"))
	}

	// Run signature verification (if any)
	if err := verify(tok, spiffeID.TrustDomain(), keyID); err != nil {
		return nil, err
	}

	return &SVID{
		ID:        spiffeID,
		Expiry:    stdClaims.Expiry.Time().UTC(),
		PublicKey: publicKey,
		KeyID:     keyID,
		token:     token,
	}, nil
}

// extractCnfJWK extracts and parses the public key from the cnf.jwk claim.
func extractCnfJWK(claims map[string]interface{}) (crypto.PublicKey, error) {
	cnfRaw, ok := claims["cnf"]
	if !ok {
		return nil, wrapErr(errors.New("token missing cnf claim"))
	}

	cnfMap, ok := cnfRaw.(map[string]interface{})
	if !ok {
		return nil, wrapErr(errors.New("cnf claim is not an object"))
	}

	jwkRaw, ok := cnfMap["jwk"]
	if !ok {
		return nil, wrapErr(errors.New("cnf claim missing jwk field"))
	}

	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil, wrapErr(errors.New("cnf.jwk is not an object"))
	}

	if _, ok := jwkMap["alg"]; !ok {
		return nil, wrapErr(errors.New("cnf.jwk missing alg field"))
	}

	data, err := json.Marshal(jwkMap)
	if err != nil {
		return nil, wrapErr(fmt.Errorf("unable to marshal cnf.jwk: %v", err))
	}

	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(data); err != nil {
		return nil, wrapErr(fmt.Errorf("unable to parse cnf.jwk: %v", err))
	}

	if !jwk.IsPublic() {
		return nil, wrapErr(errors.New("cnf.jwk must be a public key"))
	}

	return jwk.Key, nil
}

func wrapErr(err error) error {
	return fmt.Errorf("witsvid: %w", err)
}
