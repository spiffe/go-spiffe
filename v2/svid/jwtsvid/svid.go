package jwtsvid

import (
	"fmt"
	"strings"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/jwtbundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/zeebo/errs"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	jwtsvidErr = errs.Class("jwtsvid")
)

// tokenValidator validates the token and returns the claims
type tokenValidator = func(*jwt.JSONWebToken, spiffeid.TrustDomain) (map[string]interface{}, error)

// SVID represents a JWT-SVID.
type SVID struct {
	// ID is the SPIFFE ID of the JWT-SVID as present in the 'sub' claim
	ID spiffeid.ID
	// Audience is the intended recipients of JWT-SVID as present in the 'aud' claim
	Audience []string
	// Expiry is the expiration time of JWT-SVID as present in 'exp' claim
	Expiry time.Time
	// Claims is the parsed claims from token
	Claims map[string]interface{}

	// token is the serialized JWT token
	token string
}

// ParseAndValidate parses and validates a JWT-SVID token and returns the
// JWT-SVID. The JWT-SVID signature is verified using the JWT bundle source.
func ParseAndValidate(token string, bundles jwtbundle.Source, audience []string) (*SVID, error) {
	return parse(token, audience, func(tok *jwt.JSONWebToken, trustDomain spiffeid.TrustDomain) (map[string]interface{}, error) {
		// Obtain the key ID from the header
		keyID := tok.Headers[0].KeyID
		if keyID == "" {
			return nil, jwtsvidErr.New("token header missing key id")
		}

		// Get JWT Bundle
		bundle, err := bundles.GetJWTBundleForTrustDomain(trustDomain)
		if err != nil {
			return nil, jwtsvidErr.New("no bundle found for trust domain %q", trustDomain)
		}

		// Find JWT authority using the key ID from the token header
		authority, ok := bundle.FindJWTAuthority(keyID)
		if !ok {
			return nil, jwtsvidErr.New("no JWT authority %q found for trust domain %q", keyID, trustDomain)
		}

		// Obtain and verify the token claims using the obtained JWT authority
		claimsMap := make(map[string]interface{})
		if err := tok.Claims(authority, &claimsMap); err != nil {
			return nil, jwtsvidErr.New("unable to get claims from token: %v", err)
		}

		return claimsMap, nil
	})
}

// ParseInsecure parses and validates a JWT-SVID token and returns the
// JWT-SVID. The JWT-SVID signature is not verified.
func ParseInsecure(token string, audience []string) (*SVID, error) {
	return parse(token, audience, func(tok *jwt.JSONWebToken, td spiffeid.TrustDomain) (map[string]interface{}, error) {
		// Obtain the token claims insecurely, i.e. without signature verification
		claimsMap := make(map[string]interface{})
		if err := tok.UnsafeClaimsWithoutVerification(&claimsMap); err != nil {
			return nil, jwtsvidErr.New("unable to get claims from token: %v", err)
		}

		return claimsMap, nil
	})
}

// Marshal returns the JWT-SVID marshaled to a string. The returned value is
// the same token value originally passed to ParseAndValidate.
func (svid *SVID) Marshal() string {
	return svid.token
}

func parse(token string, audience []string, getClaims tokenValidator) (*SVID, error) {
	// Parse serialized token
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return nil, jwtsvidErr.New("unable to parse JWT token")
	}

	// Validates supported token signed algorithm
	if err := validateTokenHeader(tok); err != nil {
		return nil, err
	}

	// Parse out the unverified claims. We need to look up the key by the trust
	// domain of the SPIFFE ID.
	var claims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return nil, jwtsvidErr.New("unable to get claims from token: %v", err)
	}

	switch {
	case claims.Subject == "":
		return nil, jwtsvidErr.New("token missing subject claim")
	case claims.Expiry == nil:
		return nil, jwtsvidErr.New("token missing exp claim")
	}

	spiffeID, err := spiffeid.FromString(claims.Subject)
	if err != nil {
		return nil, jwtsvidErr.New("token has an invalid subject claim: %v", err)
	}

	// Create generic map of claims
	claimsMap, err := getClaims(tok, spiffeID.TrustDomain())
	if err != nil {
		return nil, err
	}

	// Validate the standard claims.
	if err := claims.Validate(jwt.Expected{
		Audience: audience,
		Time:     time.Now(),
	}); err != nil {
		// Convert expected validation errors for pretty errors
		switch err {
		case jwt.ErrExpired:
			err = jwtsvidErr.New("token has expired")
		case jwt.ErrInvalidAudience:
			err = jwtsvidErr.New("expected audience in %q (audience=%q)", audience, claims.Audience)
		}
		return nil, err
	}

	return &SVID{
		ID:       spiffeID,
		Audience: claims.Audience,
		Expiry:   claims.Expiry.Time().UTC(),
		Claims:   claimsMap,
		token:    token,
	}, nil
}

// validateTokenHeader check if JWT have only one header, it's signed for a
// supported algorithm, and it has a valid header type.
func validateTokenHeader(tok *jwt.JSONWebToken) error {
	// Only one header is expected
	if len(tok.Headers) != 1 {
		return fmt.Errorf("expected a single token header; got %d", len(tok.Headers))
	}

	hdr := &tok.Headers[0]
	err := validateTokenHeaderType(hdr)
	if err != nil {
		return err
	}

	err = validateTokenAlgorithm(hdr)
	if err != nil {
		return err
	}

	return nil
}

// validateTokenHeaderType check if JWT has a valid header type.
func validateTokenHeaderType(hdr *jose.Header) error {
	// The typ header is optional. If set, its value MUST be either JWT or JOSE.
	hdrType, present := hdr.ExtraHeaders[jose.HeaderType]
	if !present {
		return nil
	}

	// jose.HeaderType it's supposed to be a string, using a noop type
	// assertion here just to be safe.
	hdrTypeString, _ := hdrType.(string)

	// RFC7519 says:
	//   While media type names are not case sensitive, it is RECOMMENDED
	//   that "JWT" always be spelled using uppercase characters for
	//   compatibility with legacy implementations.
	//
	// And JWT-SVID spec says: If set, its value MUST be either JWT or JOSE.
	// Not sure if we should be flexible or strict on the verification.
	hdrTypeString = strings.ToUpper(hdrTypeString)
	switch hdrTypeString {
	case "JWT":
		// All SPIRE issued JWT SVIDs seems to allways have type "JWT" set.
		// TODO: Waiting for PR discussions

	case "JOSE":
		// TODO: Waiting for PR discussions

	default:
		return fmt.Errorf(`unsupported header type %#v, expecting "JWT" or "JOSE"`, hdrType)
	}

	return nil
}

// validateTokenAlgorithm json web token is signed for a supported algorithm
func validateTokenAlgorithm(hdr *jose.Header) error {
	// Make sure it has an algorithm supported by JWT-SVID
	alg := hdr.Algorithm
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512:
	default:
		return jwtsvidErr.New("unsupported token signature algorithm %q", alg)
	}

	return nil
}
