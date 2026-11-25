package jwtutil

import (
	"encoding/json"
	"errors"

	"github.com/go-jose/go-jose/v4"
)

// DecodeKey decodes a single entry of a JWK Set. It returns ok=false and no
// error when the key type isn't supported, so callers can ignore that entry
// instead of rejecting the whole set, as RFC 7517 section 5 recommends and the
// SPIFFE bundle specification requires.
func DecodeKey(raw json.RawMessage) (key jose.JSONWebKey, ok bool, err error) {
	if err := json.Unmarshal(raw, &key); err != nil {
		if errors.Is(err, jose.ErrUnsupportedKeyType) {
			return jose.JSONWebKey{}, false, nil
		}
		return jose.JSONWebKey{}, false, err
	}
	return key, true, nil
}
