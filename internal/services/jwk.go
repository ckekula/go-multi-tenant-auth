package services

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
)

// StaticKeySet is a simple kid → crypto key map, used as the backing store
// for our Keyfunc. We define it here to avoid pulling in a full JWKS library.
func init() {
	// ensure jwt package is referenced (it is, via Keyfunc type)
	_ = jwt.RegisteredClaims{}
}

// rawJWK captures only the fields we need for RSA and EC keys.
type rawJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`

	// RSA fields
	N string `json:"n"`
	E string `json:"e"`

	// EC fields
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parseJWK converts a single raw JWK JSON message into a usable public key.
// Returns the key and its kid.
func parseJWK(raw json.RawMessage) (interface{}, string, error) {
	var k rawJWK
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, "", fmt.Errorf("unmarshal JWK: %w", err)
	}

	switch k.Kty {
	case "RSA":
		return parseRSAKey(k)
	case "EC":
		return parseECKey(k)
	default:
		return nil, "", fmt.Errorf("unsupported key type: %s", k.Kty)
	}
}

func parseRSAKey(k rawJWK) (*rsa.PublicKey, string, error) {
	nBytes, err := base64URLDecode(k.N)
	if err != nil {
		return nil, "", fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64URLDecode(k.E)
	if err != nil {
		return nil, "", fmt.Errorf("decode e: %w", err)
	}

	eInt := int(new(big.Int).SetBytes(eBytes).Int64())
	pub := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}
	return pub, k.Kid, nil
}

func parseECKey(k rawJWK) (*ecdsa.PublicKey, string, error) {
	var curve elliptic.Curve
	switch k.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, "", fmt.Errorf("unsupported EC curve: %s", k.Crv)
	}

	xBytes, err := base64URLDecode(k.X)
	if err != nil {
		return nil, "", fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64URLDecode(k.Y)
	if err != nil {
		return nil, "", fmt.Errorf("decode y: %w", err)
	}

	pub := &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return pub, k.Kid, nil
}

func base64URLDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
