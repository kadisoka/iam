package jwa

// Standard key types
const (
	KeyTypeEC  = "EC"
	KeyTypeRSA = "RSA"
	KeyTypeOct = "oct"
)

// Standard algorithms. RFC7518
const (
	// HMAC-based
	AlgorithmHS256 = "HS256"
	AlgorithmHS384 = "HS384"
	AlgorithmHS512 = "HS512"
	// RSA-based
	AlgorithmRS256 = "RS256"
	AlgorithmRS384 = "RS384"
	AlgorithmRS512 = "RS512"
	// ECDSA-based
	AlgorithmES256 = "ES256"
	AlgorithmES384 = "ES384"
	AlgorithmES512 = "ES512"
	// RSASSA-PSS-based
	AlgorithmPS256 = "PS256"
	AlgorithmPS384 = "PS384"
	AlgorithmPS512 = "PS512"
	// None
	AlgorithmNone = "none"
)
