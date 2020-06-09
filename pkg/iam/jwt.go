package iam

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"io/ioutil"
	"os"
	"path/filepath"

	"github.com/citadelium/iam/pkg/jose/jwk"
)

func NewJWTKeyChainFromFiles(
	privateKeyFilename string,
	publicKeyFilenamePattern string,
) (*JWTKeyChain, error) {
	//TODO: don't assume RSA
	signer, err := loadRSAPrivateKeyFromPEMFile(privateKeyFilename, "")
	if err != nil {
		return nil, err
	}
	var signerKeyID string
	if signer != nil {
		signerKeyID = fingerprintRSAPrivateKey(signer)
	}

	var rsaVerifierKeys map[string]*rsa.PublicKey
	if publicKeyFilenamePattern != "" {
		rsaVerifierKeys, err = loadRSAPublicKeysByFileNamePattern(publicKeyFilenamePattern)
		if err != nil {
			return nil, err
		}
	}

	return &JWTKeyChain{signer: signer, signerKeyID: signerKeyID, rsaVerifierKeys: rsaVerifierKeys}, nil
}

type JWTKeyChain struct {
	signer          crypto.Signer
	signerKeyID     string
	rsaVerifierKeys map[string]*rsa.PublicKey
}

func (jwtKeyChain *JWTKeyChain) CanSign() bool {
	return jwtKeyChain.signer != nil && jwtKeyChain.signerKeyID != ""
}

func (jwtKeyChain *JWTKeyChain) GetSigner() (interface{}, string) {
	return jwtKeyChain.signer, jwtKeyChain.signerKeyID
}

func (jwtKeyChain *JWTKeyChain) GetSignerKeyID() string {
	return jwtKeyChain.signerKeyID
}

func (jwtKeyChain *JWTKeyChain) GetJWTVerifierKey(keyID string) interface{} {
	if jwtKeyChain.signer != nil {
		return jwtKeyChain.signer.Public()
	}
	if len(jwtKeyChain.rsaVerifierKeys) > 0 {
		if key := jwtKeyChain.rsaVerifierKeys[keyID]; key != nil {
			return key
		}
	}
	return nil
}

func (jwtKeyChain *JWTKeyChain) LoadVerifierKeysFromJWKSetByURL(url string) (int, error) {
	publicKeys, err := jwk.GetPublicKeysFromSetByURL(url)
	if err != nil {
		return 0, err
	}
	if len(publicKeys) > 0 && jwtKeyChain.rsaVerifierKeys == nil {
		jwtKeyChain.rsaVerifierKeys = make(map[string]*rsa.PublicKey)
	}
	for keyID, keyData := range publicKeys {
		jwtKeyChain.rsaVerifierKeys[keyID] = keyData
	}
	return len(publicKeys), nil
}

func (jwtKeyChain *JWTKeyChain) JWKSet() *jwk.Set {
	publicKeys := make(map[string]*rsa.PublicKey)
	if signerKey, signerKeyID := jwtKeyChain.GetSigner(); signerKey != nil && signerKeyID != "" {
		if rsaPrivateKey, ok := signerKey.(*rsa.PrivateKey); ok {
			publicKey := rsaPrivateKey.PublicKey
			publicKeys[signerKeyID] = &publicKey
		}
	}
	jwks := &jwk.Set{}
	jwks.AddRSAPublicKeys(publicKeys)
	jwks.AddRSAPublicKeys(jwtKeyChain.rsaVerifierKeys)
	return jwks
}

//TODO: use proper thumbprint alg https://tools.ietf.org/id/draft-jones-jose-jwk-thumbprint-00.html
func fingerprintRSAPublicKey(publicKey *rsa.PublicKey) string {
	der, _ := x509.MarshalPKIXPublicKey(publicKey)
	idBytes := sha1.Sum(der)
	return hex.EncodeToString(idBytes[:])
}

func fingerprintRSAPrivateKey(privateKey *rsa.PrivateKey) string {
	return fingerprintRSAPublicKey(&privateKey.PublicKey)
}

// see filepath.Match for the pattern
func loadRSAPublicKeysByFileNamePattern(pattern string) (map[string]*rsa.PublicKey, error) {
	fileNames, err := filepath.Glob(pattern)
	if err != nil {
		panic(err)
	}
	publicKeys := make(map[string]*rsa.PublicKey)
	for _, fileName := range fileNames {
		var fileInfo os.FileInfo
		fileInfo, err = os.Stat(fileName)
		if err != nil {
			panic(err)
		}
		if fileInfo.IsDir() {
			continue
		}
		pub, err := loadRSAPublicKeyFromPEMFile(fileName)
		if err != nil {
			panic(err)
		}
		if pub == nil {
			continue
		}
		keyID := fingerprintRSAPublicKey(pub)
		publicKeys[keyID] = pub
	}

	return publicKeys, nil
}

func loadRSAPrivateKeyFromPEMFile(fileName string, passphrase string) (*rsa.PrivateKey, error) {
	if fileName == "" {
		return nil, nil
	}

	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	pemData, _ := pem.Decode(fileBytes)
	if pemData == nil || pemData.Type != "RSA PRIVATE KEY" {
		return nil, errors.New("not a RSA private key")
	}

	var pemBytes []byte
	if passphrase != "" {
		pemBytes, err = x509.DecryptPEMBlock(pemData, []byte(passphrase))
	} else {
		pemBytes = pemData.Bytes
	}

	var parsedKey interface{}
	if parsedKey, err = x509.ParsePKCS1PrivateKey(pemBytes); err != nil {
		if parsedKey, err = x509.ParsePKCS8PrivateKey(pemBytes); err != nil {
			return nil, err
		}
	}

	privateKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not a RSA private key")
	}

	return privateKey, nil
}

func loadRSAPublicKeyFromPEMFile(fileName string) (*rsa.PublicKey, error) {
	if fileName == "" {
		return nil, nil
	}

	fileBytes, err := ioutil.ReadFile(fileName)
	if err != nil {
		return nil, err
	}

	pemData, _ := pem.Decode(fileBytes)
	if pemData == nil || pemData.Type != "RSA PUBLIC KEY" {
		return nil, errors.New("not a RSA public key")
	}

	parsedKey, err := x509.ParsePKIXPublicKey(pemData.Bytes)
	if err != nil {
		return nil, err
	}

	pubKey, ok := parsedKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not a RSA public key")
	}

	return pubKey, nil
}
