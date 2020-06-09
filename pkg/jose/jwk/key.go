package jwk

const (
	UsageSignature  = "sig"
	UsageEncryption = "enc"
)

type Key struct {
	KeyType   string `json:"kty"`
	Usage     string `json:"use"`
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
	N         string `json:"n"`
	E         string `json:"e"`
}
