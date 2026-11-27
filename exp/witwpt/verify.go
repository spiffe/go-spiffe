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

const (
	// DefaultLeeway is the clock-skew tolerance for a proof's exp and nbf. It is
	// tighter than witsvid's one minute, which would nearly double a proof's validity.
	DefaultLeeway = 10 * time.Second

	// DefaultMaxLifetime is the furthest-future exp a verifier accepts,
	// enforcing wpt-02 §2's rejection of "unreasonably far future" values.
	DefaultMaxLifetime = MaxProofLifetime
)

// VerifyOption configures a Verifier.
type VerifyOption interface {
	configureVerify(*verifyConfig)
}

type verifyConfig struct {
	replayCache    ReplayCache
	useReplayCache bool
	leeway         time.Duration
	maxLifetime    time.Duration
}

type verifyOption func(*verifyConfig)

func (fn verifyOption) configureVerify(c *verifyConfig) { fn(c) }

// Verify authenticates a peer using a verifier with default settings. Use
// NewVerifier when a replay cache or non-default timings are wanted, or to avoid
// rebuilding the verifier per request.
func Verify(ctx context.Context, witToken, wptToken string, bundles witbundle.Source,
	audience AudienceMatcher) (*witsvid.SVID, error) {
	verifier, err := NewVerifier(bundles)
	if err != nil {
		return nil, err
	}
	return verifier.Verify(ctx, witToken, wptToken, audience)
}

// WithReplayCache rejects a proof whose jti was already recorded for the same
// identity. It is off by default because an in-memory default would not cover
// replicas. NewVerifier fails if cache is nil.
func WithReplayCache(cache ReplayCache) VerifyOption {
	return verifyOption(func(c *verifyConfig) {
		c.replayCache = cache
		c.useReplayCache = true
	})
}

// WithLeeway sets the clock-skew tolerance applied to a proof's exp, nbf, and
// iat, overriding DefaultLeeway. Widening it lengthens the window in which a
// captured proof stays usable. NewVerifier fails if leeway is negative.
func WithLeeway(leeway time.Duration) VerifyOption {
	return verifyOption(func(c *verifyConfig) {
		c.leeway = leeway
	})
}

// WithMaxProofLifetime sets how far into the future a proof's exp may sit,
// overriding DefaultMaxLifetime. NewVerifier fails if maxLifetime is not positive.
func WithMaxProofLifetime(maxLifetime time.Duration) VerifyOption {
	return verifyOption(func(c *verifyConfig) {
		c.maxLifetime = maxLifetime
	})
}

// Verifier validates a WIT-SVID and its proof of possession. It is safe for
// concurrent use.
type Verifier struct {
	bundles witbundle.Source
	config  verifyConfig
}

// NewVerifier returns a Verifier validating WIT-SVIDs against bundles. It fails
// if bundles is nil or an option holds an invalid value.
func NewVerifier(bundles witbundle.Source, opts ...VerifyOption) (*Verifier, error) {
	if bundles == nil {
		return nil, wrapErr(errors.New("no bundle source provided"))
	}
	config := verifyConfig{
		leeway:      DefaultLeeway,
		maxLifetime: DefaultMaxLifetime,
	}
	for _, opt := range opts {
		opt.configureVerify(&config)
	}
	switch {
	case config.useReplayCache && config.replayCache == nil:
		return nil, wrapErr(errors.New("replay cache must not be nil"))
	case config.leeway < 0:
		return nil, wrapErr(fmt.Errorf("leeway must not be negative, got %s", config.leeway))
	case config.maxLifetime <= 0:
		return nil, wrapErr(fmt.Errorf("max proof lifetime must be positive, got %s", config.maxLifetime))
	}
	return &Verifier{bundles: bundles, config: config}, nil
}

// Verify authenticates a peer from its raw WIT and WPT tokens, validating the
// WIT against the bundle before checking the proof against its cnf key.
// Verification failures are *Error; their messages should not be sent to the peer.
func (v *Verifier) Verify(ctx context.Context, witToken, wptToken string,
	audience AudienceMatcher) (*witsvid.SVID, error) {
	if audience == nil {
		return nil, wrapErr(errors.New("no audience matcher provided"))
	}
	if witToken == "" {
		return nil, newError(StageWIT, errors.New("no WIT-SVID token presented"))
	}

	// Until the credential is validated there is no key to trust.
	svid, err := witsvid.ParseAndValidate(witToken, v.bundles)
	if err != nil {
		return nil, newError(StageWIT, err)
	}

	claims, err := v.verifyProof(witToken, wptToken, svid)
	if err != nil {
		return nil, newError(StageProof, err)
	}
	if err := audience(claims.audience); err != nil {
		return nil, newError(StageProof, err)
	}

	// Replay is checked last, once the proof is otherwise valid, so a rejected
	// proof does not consume its jti. The record lasts leeway past exp, since
	// that is how long the proof stays acceptable.
	if v.config.replayCache != nil {
		dropAfter := claims.expiry.Add(v.config.leeway)
		err := v.config.replayCache.CheckAndRecord(ctx, svid.ID, claims.id, dropAfter)
		switch {
		case errors.Is(err, ErrReplayed):
			return nil, newError(StageReplay, err)
		case err != nil:
			return nil, newError(StageReplayCache, err)
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

	// alg MUST string-equal the WIT's cnf.jwk.alg (wpt-02 §2), so it is the only
	// algorithm accepted. witsvid has already refused "none" and symmetric ones.
	expectedAlg := svid.ConfirmationAlgorithm()
	tok, err := jwt.ParseSigned(wptToken, []jose.SignatureAlgorithm{jose.SignatureAlgorithm(expectedAlg)})
	if err != nil {
		return out, fmt.Errorf("unable to parse proof token as %s, the WIT-SVID's cnf.jwk alg: %w",
			expectedAlg, err)
	}

	header := tok.Headers[0]

	// typ MUST be wpt+jwt, so a token minted for another purpose cannot be used
	// as a proof.
	if typ, _ := header.ExtraHeaders[jose.HeaderType].(string); typ != proofType {
		return out, fmt.Errorf("proof header type must be %q, got %q", proofType, typ)
	}

	// Proof of possession: the signature must verify under the cnf key.
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
	expectedWTH := WITHash(witToken)
	if subtle.ConstantTimeCompare([]byte(wth), []byte(expectedWTH)) != 1 {
		return out, errors.New("proof wth claim is not bound to the presented WIT-SVID")
	}

	// Checked here so a custom AudienceMatcher never sees a proof without aud.
	audience, _ := raw["aud"].(string)
	if audience == "" {
		return out, errors.New("proof aud claim must be a non-empty string")
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

	// wpt-02 §2: unreasonably far future exp values SHOULD be rejected.
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
		case errors.Is(err, jwt.ErrIssuedInTheFuture):
			return out, errors.New("proof was issued in the future")
		default:
			return out, err
		}
	}

	out = proofClaims{audience: audience, id: jti, expiry: expiry}
	return out, nil
}

// bindingClaims are the WPT claims that bind a proof to some other credential
// travelling with the request: a Txn-Token or another token (wpt-02 §2), and an
// OAuth access token (ath, defined only before wpt-02).
var bindingClaims = []string{"ath", "tth", "oth"}

// rejectTokenBindings fails closed on bindings this package does not enforce,
// which would otherwise make a stolen bearer token look bound.
func rejectTokenBindings(raw map[string]any) error {
	for _, claim := range bindingClaims {
		if _, ok := raw[claim]; ok {
			return fmt.Errorf("proof carries the %q claim, and token binding is not "+
				"supported by this verifier", claim)
		}
	}
	return nil
}
