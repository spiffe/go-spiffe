// Package witwpt implements the Workload Proof Token (WPT) proof-of-possession
// protocol for WIT-SVIDs, as specified by draft-ietf-wimse-wpt-01. A workload
// mints a short-lived WPT signed with the private key matching the WIT-SVID's
// cnf.jwk claim, binding the proof to the credential (wth) and to the request
// target (aud).
//
// This package is transport neutral. See exp/withttp for the net/http
// integration.
package witwpt

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
)

const (
	// DefaultProofLifetime is how far ahead a minted proof's exp is set. The
	// draft calls for a lifetime of "minutes or seconds".
	DefaultProofLifetime = 60 * time.Second

	// DefaultLeeway is the clock-skew tolerance a verifier applies to a proof's
	// exp and nbf. It is tighter than the one-minute jwt.DefaultLeeway witsvid
	// applies to the WIT, which would nearly double a proof's validity.
	DefaultLeeway = 10 * time.Second

	// DefaultMaxLifetime is the furthest-future exp a verifier accepts,
	// enforcing wpt-01 §2's rejection of "unreasonably far future" values.
	DefaultMaxLifetime = 5 * time.Minute
)

// proofType is the required typ header of a WPT (wpt-01 §2).
const proofType = "wpt+jwt"

// jtiBytes is the entropy behind each proof's jti, per wpt-01 §2's suggested
// 128 random bits.
const jtiBytes = 16

// MintOption configures Mint.
type MintOption interface {
	configureMint(*mintConfig)
}

type mintConfig struct {
	lifetime time.Duration
}

type mintOption func(*mintConfig)

func (fn mintOption) configureMint(c *mintConfig) { fn(c) }

// WithProofLifetime sets how far ahead the minted proof's exp is placed,
// overriding DefaultProofLifetime. Raising it past the verifier's maximum
// lifetime causes the proof to be rejected.
func WithProofLifetime(lifetime time.Duration) MintOption {
	return mintOption(func(c *mintConfig) {
		c.lifetime = lifetime
	})
}

// Mint returns a Workload Proof Token, in JWS compact serialization, proving
// possession of svid's confirmation key, bound to svid and scoped to audience.
//
// audience should be the request target URI without query or fragment
// (wpt-01 §2). A fresh proof should be minted per request.
func Mint(svid *witsvid.SVID, audience string, opts ...MintOption) (string, error) {
	if svid == nil {
		return "", wrapErr(errors.New("no WIT-SVID provided"))
	}
	if audience == "" {
		return "", wrapErr(errors.New("no audience provided"))
	}
	if svid.PrivateKey == nil {
		return "", wrapErr(errors.New("WIT-SVID has no private key, so possession cannot be proven"))
	}

	witToken := svid.Marshal()
	if witToken == "" {
		return "", wrapErr(errors.New("WIT-SVID has no token to bind the proof to"))
	}

	// wpt-01 §2 requires the proof's alg to string-equal the WIT's cnf.jwk.alg.
	alg, err := confirmationAlgorithm(svid)
	if err != nil {
		return "", err
	}

	config := &mintConfig{lifetime: DefaultProofLifetime}
	for _, opt := range opts {
		opt.configureMint(config)
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: alg, Key: svid.PrivateKey},
		(&jose.SignerOptions{}).WithType(proofType),
	)
	if err != nil {
		return "", wrapErr(fmt.Errorf("unable to build proof signer: %w", err))
	}

	now := time.Now()
	proof, err := jwt.Signed(signer).Claims(map[string]any{
		"aud": audience,
		"exp": jwt.NewNumericDate(now.Add(config.lifetime)),
		"iat": jwt.NewNumericDate(now),
		"jti": jti,
		"wth": WITThumbprint(witToken),
	}).Serialize()
	if err != nil {
		return "", wrapErr(fmt.Errorf("unable to sign proof: %w", err))
	}
	return proof, nil
}

// WITThumbprint returns the wth claim value binding a proof to a WIT-SVID:
// base64url(SHA-256(ASCII(token))) over the compact serialization, per
// wpt-01 §2. This hashes the token itself, not an RFC 7638 JWK thumbprint of
// the confirmation key.
func WITThumbprint(witToken string) string {
	sum := sha256.Sum256([]byte(witToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// confirmationAlgorithm reads cnf.jwk.alg from the credential's claims. witsvid
// already validated it is present and a supported asymmetric algorithm.
func confirmationAlgorithm(svid *witsvid.SVID) (jose.SignatureAlgorithm, error) {
	cnf, ok := svid.Claims["cnf"].(map[string]any)
	if !ok {
		return "", wrapErr(errors.New("WIT-SVID claims have no cnf object"))
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		return "", wrapErr(errors.New("WIT-SVID cnf claim has no jwk object"))
	}
	alg, ok := jwk["alg"].(string)
	if !ok || alg == "" {
		return "", wrapErr(errors.New("WIT-SVID cnf.jwk has no alg"))
	}
	return jose.SignatureAlgorithm(alg), nil
}

func newJTI() (string, error) {
	raw := make([]byte, jtiBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", wrapErr(fmt.Errorf("unable to generate proof id: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
