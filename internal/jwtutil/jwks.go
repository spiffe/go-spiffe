package jwtutil

import (
	"encoding/json"
	"errors"

	"github.com/go-jose/go-jose/v4"
	josejson "github.com/go-jose/go-jose/v4/json"
)

// DecodeKey decodes a single entry of a JWK Set. It returns ok=false and no
// error when the key type isn't supported, so callers can ignore that entry
// instead of rejecting the whole set, as RFC 7517 section 5 recommends and the
// SPIFFE bundle specification requires.
func DecodeKey(raw json.RawMessage) (key jose.JSONWebKey, ok bool, err error) {
	// go-jose decodes known members before it checks kty, so an unsupported
	// kty with a bad member would fail. Check kty first, with go-jose's
	// decoder so that both steps read the same member.
	var entry struct {
		KeyType string `json:"kty"`
	}
	if err := josejson.Unmarshal(raw, &entry); err != nil {
		return jose.JSONWebKey{}, false, err
	}
	// The key type is required, so go-jose is left to reject a missing one.
	if entry.KeyType != "" && !decodable(entry.KeyType) {
		return jose.JSONWebKey{}, false, nil
	}

	if err := json.Unmarshal(raw, &key); err != nil {
		// go-jose reports key types it knows but can't decode, such as an
		// OKP key on an unsupported curve.
		if errors.Is(err, jose.ErrUnsupportedKeyType) {
			return jose.JSONWebKey{}, false, nil
		}
		return jose.JSONWebKey{}, false, err
	}
	return key, true, nil
}

// decodable reports whether go-jose decodes keys of the given type.
func decodable(keyType string) bool {
	switch keyType {
	case "EC", "RSA", "OKP", "oct":
		return true
	case "AKP":
		return mldsaSupported
	default:
		return false
	}
}
