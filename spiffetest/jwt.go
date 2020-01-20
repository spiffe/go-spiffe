package spiffetest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
	"gopkg.in/square/go-jose.v2/jwt"
)

// TokenGenerator generates a token signing it with provided signer
type TokenGenerator struct {
	TB       testing.TB
	Issuer   string
	SpiffeID string
	Audience []string
	Expires  time.Time
	Signer   crypto.Signer
	KeyID    string
}

// Generate generates a signed string token
func (t *TokenGenerator) Generate() string {
	// build up claims
	claims := jwt.Claims{
		Subject:  t.SpiffeID,
		Issuer:   t.Issuer,
		Expiry:   jwt.NewNumericDate(t.Expires),
		Audience: t.Audience,
		IssuedAt: jwt.NewNumericDate(time.Now()),
	}

	// get signer algorithm
	alg, err := t.getSignerAlgorithm()
	require.NoError(t.TB, err)

	// create signer using crypto.Signer and its algorithm along with provided key ID
	jwtSigner, err := jose.NewSigner(
		jose.SigningKey{
			Algorithm: alg,
			Key: jose.JSONWebKey{
				Key:   cryptosigner.Opaque(t.Signer),
				KeyID: t.KeyID,
			},
		},
		new(jose.SignerOptions).WithType("JWT"),
	)
	require.NoError(t.TB, err)

	/// sign claim and  serializes it
	token, err := jwt.Signed(jwtSigner).Claims(claims).CompactSerialize()
	require.NoError(t.TB, err)

	return token
}

// getSignerAlgorithm deduces signer algorithm and return it
func (t *TokenGenerator) getSignerAlgorithm() (jose.SignatureAlgorithm, error) {
	switch publicKey := t.Signer.Public().(type) {
	case *rsa.PublicKey:
		// Prevent the use of keys smaller than 2048 bits
		if publicKey.Size() < 256 {
			return "", fmt.Errorf("unsupported RSA key size: %d", publicKey.Size())
		}
		return jose.RS256, nil
	case *ecdsa.PublicKey:
		params := publicKey.Params()
		switch params.BitSize {
		case 256:
			return jose.ES256, nil
		case 384:
			return jose.ES384, nil
		default:
			return "", fmt.Errorf("unable to determine signature algorithm for EC public key size %d", params.BitSize)
		}
	default:
		return "", fmt.Errorf("unable to determine signature algorithm for public key type %T", publicKey)
	}
}
