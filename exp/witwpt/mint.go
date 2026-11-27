// Package witwpt implements the Workload Proof Token (WPT) proof-of-possession
// protocol for WIT-SVIDs, as specified by draft-ietf-wimse-wpt-02. A workload
// mints a short-lived WPT signed with the private key matching the WIT-SVID's
// cnf.jwk claim, binding the proof to the credential (wth) and to the request
// target (aud).
//
// This package is transport neutral.
package witwpt

import (
	"crypto"
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

	// MaxProofLifetime is the longest lifetime Mint accepts (wpt-02 §2: WPT
	// lifetimes MUST be short).
	MaxProofLifetime = 5 * time.Minute
)

// proofType is the required typ header of a WPT (wpt-02 §2).
const proofType = "wpt+jwt"

// jtiBytes gives each jti 128 random bits (wpt-02 §2).
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

// WithProofLifetime overrides DefaultProofLifetime for the minted proof's exp.
// Mint rejects lifetimes under a second, since exp has whole-second precision,
// and over MaxProofLifetime.
func WithProofLifetime(lifetime time.Duration) MintOption {
	return mintOption(func(c *mintConfig) {
		c.lifetime = lifetime
	})
}

// Mint returns a Workload Proof Token, in JWS compact serialization, proving
// possession of svid's confirmation key, bound to svid and scoped to audience.
//
// audience should be the request target URI without query or fragment
// (wpt-02 §2). A fresh proof should be minted per request.
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
	if !time.Now().Before(svid.Expiry) {
		return "", wrapErr(fmt.Errorf("WIT-SVID expired at %s", svid.Expiry.UTC().Format(time.RFC3339)))
	}

	if err := checkKeyMatches(svid); err != nil {
		return "", err
	}

	config := &mintConfig{lifetime: DefaultProofLifetime}
	for _, opt := range opts {
		opt.configureMint(config)
	}
	if config.lifetime < time.Second || config.lifetime > MaxProofLifetime {
		return "", wrapErr(fmt.Errorf("proof lifetime must be between 1s and %s, got %s",
			MaxProofLifetime, config.lifetime))
	}

	jti, err := newJTI()
	if err != nil {
		return "", err
	}

	// wpt-02 §2 requires the proof's alg to string-equal the WIT's cnf.jwk.alg.
	alg := jose.SignatureAlgorithm(svid.ConfirmationAlgorithm())
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
		"wth": WITHash(witToken),
	}).Serialize()
	if err != nil {
		return "", wrapErr(fmt.Errorf("unable to sign proof: %w", err))
	}
	return proof, nil
}

// WITHash returns the wth claim for a WIT-SVID token: base64url(SHA-256(token))
// over its compact serialization (wpt-02 §2).
func WITHash(witToken string) string {
	sum := sha256.Sum256([]byte(witToken))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// checkKeyMatches verifies that the private key pairs with the cnf.jwk public key.
func checkKeyMatches(svid *witsvid.SVID) error {
	signer, ok := svid.PrivateKey.(crypto.Signer)
	if !ok {
		return wrapErr(fmt.Errorf("WIT-SVID private key of type %T cannot sign", svid.PrivateKey))
	}
	public, ok := signer.Public().(interface{ Equal(crypto.PublicKey) bool })
	if !ok || !public.Equal(svid.PublicKey) {
		return wrapErr(errors.New("WIT-SVID private key does not match its cnf.jwk"))
	}
	return nil
}

func newJTI() (string, error) {
	raw := make([]byte, jtiBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", wrapErr(fmt.Errorf("unable to generate proof id: %w", err))
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
