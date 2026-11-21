package witwpt

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/spiffe/go-spiffe/v2/exp/bundle/witbundle"
	"github.com/spiffe/go-spiffe/v2/exp/svid/witsvid"
)

// allowedProofAlgorithms mirrors the asymmetric algorithms witsvid permits for a
// confirmation key. wpt-01 §2 requires "none" and symmetric algorithms be
// rejected.
var allowedProofAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256, jose.RS384, jose.RS512,
	jose.ES256, jose.ES384, jose.ES512,
	jose.PS256, jose.PS384, jose.PS512,
}

const (
	// DefaultLeeway is the clock-skew tolerance a verifier applies to a proof's
	// exp and nbf. It is tighter than the one-minute jwt.DefaultLeeway witsvid
	// applies to the WIT, which would nearly double a proof's validity.
	DefaultLeeway = 10 * time.Second

	// DefaultMaxLifetime is the furthest-future exp a verifier accepts,
	// enforcing wpt-01 §2's rejection of "unreasonably far future" values.
	DefaultMaxLifetime = 5 * time.Minute
)

// VerifyOption configures a Verifier.
type VerifyOption interface {
	configureVerify(*verifyConfig)
}

type verifyConfig struct {
	replayCache ReplayCache
	leeway      time.Duration
	maxLifetime time.Duration
}

type verifyOption func(*verifyConfig)

func (fn verifyOption) configureVerify(c *verifyConfig) { fn(c) }

// WithReplayCache enables replay protection, rejecting a proof whose jti has
// already been recorded for the presenting identity. It is off by default,
// since NewMemoryReplayCache covers a single process only and enabling it by
// default would look like complete coverage across replicas.
func WithReplayCache(cache ReplayCache) VerifyOption {
	return verifyOption(func(c *verifyConfig) {
		c.replayCache = cache
	})
}

// WithLeeway sets the clock-skew tolerance applied to a proof's exp and nbf,
// overriding DefaultLeeway. Widening it lengthens the window in which a
// captured proof stays usable.
func WithLeeway(leeway time.Duration) VerifyOption {
	return verifyOption(func(c *verifyConfig) {
		c.leeway = leeway
	})
}

// WithMaxProofLifetime sets how far into the future a proof's exp may sit,
// overriding DefaultMaxLifetime. It also bounds the memory replay cache's
// footprint, since no record is kept past it.
func WithMaxProofLifetime(maxLifetime time.Duration) VerifyOption {
	return verifyOption(func(c *verifyConfig) {
		c.maxLifetime = maxLifetime
	})
}

// Verifier validates a WIT-SVID and its proof of possession. It is safe for
// concurrent use; build one at startup and share it so every transport shares
// its settings and replay cache.
type Verifier struct {
	bundles witbundle.Source
	config  verifyConfig
}

// NewVerifier returns a Verifier validating WIT-SVIDs against bundles.
func NewVerifier(bundles witbundle.Source, opts ...VerifyOption) *Verifier {
	config := verifyConfig{
		leeway:      DefaultLeeway,
		maxLifetime: DefaultMaxLifetime,
	}
	for _, opt := range opts {
		opt.configureVerify(&config)
	}
	return &Verifier{bundles: bundles, config: config}
}

// Verify authenticates a peer from the two raw tokens it presented, returning
// the verified WIT-SVID. audience decides which aud values are acceptable for
// this request and must not be nil.
//
// It takes raw tokens rather than a parsed SVID so the normative order is
// unskippable: the WIT-SVID is validated against the trust bundle first, and
// only then is the proof checked against the confirmation key it named.
//
// A failure is returned as *Error carrying the Stage that rejected it. Its
// message should not be surfaced to a remote peer.
func (v *Verifier) Verify(ctx context.Context, witToken, wptToken string,
	audience AudienceMatcher) (*witsvid.SVID, error) {
	if audience == nil {
		return nil, newError(StageProof, errors.New("no audience matcher provided"))
	}
	if witToken == "" {
		return nil, newError(StageWIT, errors.New("no WIT-SVID token presented"))
	}

	// Step 1: the credential. Until this succeeds there is no key to trust.
	svid, err := witsvid.ParseAndValidate(witToken, v.bundles)
	if err != nil {
		return nil, newError(StageWIT, err)
	}

	// Step 2: the proof, against the confirmation key the credential named.
	claims, err := v.verifyProof(witToken, wptToken, svid)
	if err != nil {
		return nil, newError(StageProof, err)
	}
	if err := audience(claims.audience); err != nil {
		return nil, newError(StageProof, err)
	}

	// Step 3: replay, once the identity is known so a jti cannot be claimed
	// across workloads. The record lasts leeway past exp, since that is how long
	// the proof stays acceptable.
	if v.config.replayCache != nil {
		dropAfter := claims.expiry.Add(v.config.leeway)
		if err := v.config.replayCache.CheckAndRecord(ctx, svid.ID, claims.id, dropAfter); err != nil {
			return nil, newError(StageReplay, err)
		}
	}
	return svid, nil
}

// proofClaims is the subset of a verified proof the verifier acts on.
type proofClaims struct {
	audience string
	id       string
	expiry   time.Time
}

func (v *Verifier) verifyProof(witToken, wptToken string, svid *witsvid.SVID) (proofClaims, error) {
	var out proofClaims

	if wptToken == "" {
		return out, errors.New("no proof token presented")
	}

	tok, err := jwt.ParseSigned(wptToken, allowedProofAlgorithms)
	if err != nil {
		return out, fmt.Errorf("unable to parse proof token: %w", err)
	}

	header := tok.Headers[0]

	// typ MUST be wpt+jwt, so a token minted for another purpose cannot be used
	// as a proof.
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != proofType {
		return out, fmt.Errorf("proof header type must be %q, got %q", proofType, typ)
	}

	// alg MUST string-equal the WIT's cnf.jwk.alg (wpt-01 §2), so the presenter
	// cannot choose it.
	expectedAlg, err := confirmationAlgorithm(svid)
	if err != nil {
		return out, err
	}
	if header.Algorithm != string(expectedAlg) {
		return out, fmt.Errorf("proof alg %q does not match the WIT-SVID's cnf.jwk alg %q",
			header.Algorithm, expectedAlg)
	}

	// The signature must verify under the confirmation public key: this is the
	// proof of possession.
	var raw map[string]any
	if err := tok.Claims(svid.PublicKey, &raw); err != nil {
		return out, fmt.Errorf("proof signature verification failed: %w", err)
	}

	// wth binds the proof to this exact credential, recomputed over the token as
	// received so a re-serialization cannot shift the bytes.
	wth, _ := raw["wth"].(string)
	if wth == "" {
		return out, errors.New("proof is missing the wth claim")
	}
	expectedWTH := WITThumbprint(witToken)
	if subtle.ConstantTimeCompare([]byte(wth), []byte(expectedWTH)) != 1 {
		return out, errors.New("proof wth claim is not bound to the presented WIT-SVID")
	}

	// jti is required regardless of whether a replay cache is configured.
	jti, _ := raw["jti"].(string)
	if jti == "" {
		return out, errors.New("proof is missing the jti claim")
	}

	if err := rejectTokenBindings(raw); err != nil {
		return out, err
	}

	var std jwt.Claims
	if err := tok.UnsafeClaimsWithoutVerification(&std); err != nil {
		return out, fmt.Errorf("unable to read proof claims: %w", err)
	}
	if std.Expiry == nil {
		return out, errors.New("proof is missing the exp claim")
	}

	now := time.Now()
	expiry := std.Expiry.Time()

	// wpt-01 §2: unreasonably far future exp values SHOULD be rejected.
	if expiry.After(now.Add(v.config.maxLifetime + v.config.leeway)) {
		return out, fmt.Errorf("proof exp is too far in the future (max lifetime %s)",
			v.config.maxLifetime)
	}

	if err := std.ValidateWithLeeway(jwt.Expected{Time: now}, v.config.leeway); err != nil {
		switch {
		case errors.Is(err, jwt.ErrExpired):
			// The leeway is named so an operator sees skew, not policy, as the cause.
			return out, fmt.Errorf("proof has expired (clock skew beyond %s is not tolerated)",
				v.config.leeway)
		case errors.Is(err, jwt.ErrNotValidYet):
			return out, errors.New("proof is not yet valid")
		default:
			return out, err
		}
	}

	audience, _ := raw["aud"].(string)
	out = proofClaims{audience: audience, id: jti, expiry: expiry}
	return out, nil
}

// bindingClaims are the WPT claims that bind a proof to some other credential
// travelling with the request (wpt-01 §2): an OAuth access token, a Txn-Token, or
// another end-user-context token.
var bindingClaims = []string{"ath", "tth", "oth"}

// rejectTokenBindings fails closed on a binding this package does not model.
// Ignoring one would let a stolen bearer token look bound when it is not, and
// wpt-01 §2 requires rejecting an oth entry the recipient does not understand.
func rejectTokenBindings(raw map[string]any) error {
	for _, claim := range bindingClaims {
		if _, ok := raw[claim]; ok {
			return fmt.Errorf("proof carries the %q claim, and token binding is not "+
				"supported by this verifier", claim)
		}
	}
	return nil
}

// Verify authenticates a peer using a verifier with default settings. Use
// NewVerifier when a replay cache or non-default timings are wanted, or to avoid
// rebuilding the verifier per request.
func Verify(ctx context.Context, witToken, wptToken string, bundles witbundle.Source,
	audience AudienceMatcher) (*witsvid.SVID, error) {
	return NewVerifier(bundles).Verify(ctx, witToken, wptToken, audience)
}
