package jwtsvid

import (
	"errors"
	"fmt"
	"time"

	"github.com/spiffe/go-spiffe/spiffe"
	"github.com/spiffe/go-spiffe/spiffe/svid/bundle"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

// validateTokenAlgorithm json web token have only one header, and it is signed for a supported algorithm
func validateTokenAlgorithm(tok *jwt.JSONWebToken) error {
	// Only one header is expected
	if len(tok.Headers) != 1 {
		return fmt.Errorf("expected a single token header; got %d", len(tok.Headers))
	}

	// Make sure it has an algorithm supported by JWT-SVID
	alg := tok.Headers[0].Algorithm
	switch jose.SignatureAlgorithm(alg) {
	case jose.RS256, jose.RS384, jose.RS512,
		jose.ES256, jose.ES384, jose.ES512,
		jose.PS256, jose.PS384, jose.PS512:
	default:
		return fmt.Errorf("unsupported token signature algorithm %q", alg)
	}

	return nil
}

// validateToken verify if token is signed by provided token and audience its audience
func validateToken(token string, keyStore bundle.KeyStore, audience []string) (string, map[string]interface{}, error) {
	// Parse serialized token
	tok, err := jwt.ParseSigned(token)
	if err != nil {
		return "", nil, errors.New("unable to parse JWT token")
	}

	// Validates supported token signed algorithm
	if err := validateTokenAlgorithm(tok); err != nil {
		return "", nil, err
	}

	// Obtain the key ID from the header
	keyID := tok.Headers[0].KeyID
	if keyID == "" {
		return "", nil, errors.New("token header missing key id")
	}

	// Parse out the unverified claims. We need to look up the key by the trust
	// domain of the SPIFFE ID. We'll verify the signature on the claims below
	// when creating the generic map of claims that we return to the caller.
	var claims jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&claims); err != nil {
		return "", nil, fmt.Errorf("no able to get claims from token: %v", err)
	}
	if claims.Subject == "" {
		return "", nil, errors.New("token missing subject claim")
	}
	spiffeID, err := spiffe.ParseID(claims.Subject, spiffe.AllowAnyTrustDomainWorkload())
	if err != nil {
		return "", nil, fmt.Errorf("token has in invalid subject claim: %v", err)
	}

	// Construct the trust domain id from the SPIFFE ID and look up key by ID
	trustDomainID := spiffe.TrustDomainID(spiffeID.Host)
	key, err := keyStore.FindJWTKey(trustDomainID, keyID)
	if err != nil {
		return "", nil, err
	}

	// Now obtain the generic claims map verified using the obtained key
	claimsMap := make(map[string]interface{})
	if err := tok.Claims(key, &claimsMap); err != nil {
		return "", nil, fmt.Errorf("unable to get claims from token: %v", err)
	}

	// Now that the signature over the claims has been verified, validate the
	// standard claims.
	if err := claims.Validate(jwt.Expected{
		Audience: audience,
		Time:     time.Now(),
	}); err != nil {
		// Convert expected validation errors for pretty errors
		switch err {
		case jwt.ErrExpired:
			err = errors.New("token has expired")
		case jwt.ErrInvalidAudience:
			err = fmt.Errorf("expected audience in %q (audience=%q)", audience, claims.Audience)
		}
		return "", nil, err
	}

	return spiffeID.String(), claimsMap, nil
}

// GetSpiffeID get spiffeID from a jwt token validated against a provided bundle
func GetSpiffeID(token string, keyStore bundle.KeyStore, audience []string) (string, error) {
	spiffeID, _, err := validateToken(token, keyStore, audience)
	if err != nil {
		return "", err
	}

	return spiffeID, nil
}
