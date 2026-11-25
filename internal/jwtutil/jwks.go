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
	// go-jose decodes every member it knows before it looks at the key type,
	// so it fails on an unknown key type that gives one of those members a
	// different shape. The key type is checked first to ignore such entries.
	var entry struct {
		KeyType string `json:"kty"`
	}
	if err := json.Unmarshal(raw, &entry); err != nil {
		return jose.JSONWebKey{}, false, err
	}
	switch entry.KeyType {
	case "EC", "RSA", "OKP", "oct":
		// The key types go-jose decodes.
	case "":
		// The key type is required, so go-jose is left to reject the entry.
	default:
		return jose.JSONWebKey{}, false, nil
	}

	if err := json.Unmarshal(raw, &key); err != nil {
		// go-jose also reports key types it knows but can't decode, such as
		// an OKP key on an unsupported curve.
		if errors.Is(err, jose.ErrUnsupportedKeyType) {
			return jose.JSONWebKey{}, false, nil
		}
		return jose.JSONWebKey{}, false, err
	}
	return key, true, nil
}
