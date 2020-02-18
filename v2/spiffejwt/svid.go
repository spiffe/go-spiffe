package spiffejwt

import (
	"crypto"
	"time"

	"github.com/spiffe/go-spiffe/v2/spiffeid"
)

// KeyStore is an interface used to locate the public key for a signed JWT-SVID.
type KeyStore interface {
	GetJWTKeyForTrustDomain(trustDomain spiffeid.TrustDomain, keyID string) (crypto.PublicKey, error)
}

// SVID represents a JWT-SVID.
type SVID struct {
	Token string

	ID spiffeid.ID

	// TODO: denormalize values for things like expiration and issuance
	// so the token claims don't have to be interpreted
}

// Mint signs a new JWT-SVID. In accordance with the JWT-SVID specification,
// extra claims MAY be used but might impact interoperability.
func Mint(signer crypto.Signer, id spiffeid.ID, audience []string, expiresAt time.Time, extraClaims map[string]interface{}) (*SVID, error) {
	panic("not implemented")
}

// ParseAndValidate parses and validates a JWT-SVID token and returns the
// JWT-SVID. The KeyStore is used to obtain the public key as identified by the
// SPIFFE ID of the trust domain and key ID.
func ParseAndValidate(token string, keys KeyStore, audience []string, validator Validator) (*SVID, error) {
	panic("not implemented")
}
