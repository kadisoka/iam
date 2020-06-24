package iam

import (
	"crypto"
	"crypto/rsa"
	_ "crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"path/filepath"

	"github.com/square/go-jose/v3"
)

var thumbprintHasher = crypto.SHA256

func NewJWTKeyChainFromFiles(
	privateKeyFilename string,
	publicKeyFilenamePattern string,
) (*JWTKeyChain, error) {
	//TODO: don't assume RSA
	signerKey, err := loadRSAPrivateKeyFromPEMFile(privateKeyFilename, "")
	if err != nil {
		return nil, err
	}
	var signerKeyID string
	if signerKey != nil {
		signerKeyID, err = thumbprintKey(signerKey)
		if err != nil {
			panic(err)
		}
	}

	keySet := make(map[string]interface{})
	if publicKeyFilenamePattern != "" {
		rsaVerifierKeys, err := loadRSAPublicKeysByFileNamePattern(publicKeyFilenamePattern)
		if err != nil {
			return nil, err
		}
		for k, v := range rsaVerifierKeys {
			keySet[k] = v
		}
	}

	return &JWTKeyChain{signerKey: signerKey, signerKeyID: signerKeyID, keySet: keySet}, nil
}

type JWTKeyChain struct {
	signerKey   crypto.Signer
	signerKeyID string
	keySet      map[string]interface{}
}

func (jwtKeyChain JWTKeyChain) CanSign() bool {
	return jwtKeyChain.signerKey != nil && jwtKeyChain.signerKeyID != ""
}

func (jwtKeyChain JWTKeyChain) GetSigner() (jose.Signer, error) {
	if !jwtKeyChain.CanSign() {
		return nil, nil
	}
	return jose.NewSigner(jose.SigningKey{
		Key:       jwtKeyChain.signerKey,
		Algorithm: jose.RS256,
	}, &jose.SignerOptions{
		ExtraHeaders: map[jose.HeaderKey]interface{}{
			jose.HeaderKey("kid"): jwtKeyChain.signerKeyID,
		},
	})
}

func (jwtKeyChain JWTKeyChain) GetSignedVerifierKey(keyID string) interface{} {
	if jwtKeyChain.signerKey != nil && jwtKeyChain.signerKeyID == keyID {
		return jwtKeyChain.signerKey.Public()
	}
	if len(jwtKeyChain.keySet) > 0 {
		if key := jwtKeyChain.keySet[keyID]; key != nil {
			return key
		}
	}
	return nil
}

func (jwtKeyChain *JWTKeyChain) LoadVerifierKeysFromJWKSetByURL(jwksURL string) (int, error) {
	publicKeys, err := loadJSONWebKeySetByURL(jwksURL)
	if err != nil {
		return 0, err
	}
	if len(publicKeys) > 0 && jwtKeyChain.keySet == nil {
		jwtKeyChain.keySet = make(map[string]interface{})
	}
	for keyID, keyData := range publicKeys {
		jwtKeyChain.keySet[keyID] = keyData
	}
	return len(publicKeys), nil
}

func (jwtKeyChain JWTKeyChain) JWKSet() jose.JSONWebKeySet {
	var keys []jose.JSONWebKey

	// Add active signer key
	signerKey := jwtKeyChain.signerKey
	signerKeyID := jwtKeyChain.signerKeyID
	if signerKey != nil && signerKeyID != "" {
		if rsaPrivateKey, ok := signerKey.(*rsa.PrivateKey); ok {
			publicKey := rsaPrivateKey.PublicKey
			keys = append(keys, jose.JSONWebKey{
				KeyID:     signerKeyID,
				Key:       &publicKey,
				Use:       "sig",
				Algorithm: string(jose.RS256),
			})
		}
	}

	// Add verifier keys
	for kid, key := range jwtKeyChain.keySet {
		keys = append(keys, jose.JSONWebKey{
			KeyID:     kid,
			Key:       key,
			Use:       "sig",
			Algorithm: string(jose.RS256),
		})
	}

	return jose.JSONWebKeySet{Keys: keys}
}

func thumbprintKey(key interface{}) (thumbprintStr string, err error) {
	k := &jose.JSONWebKey{Key: key}
	tpBytes, err := k.Thumbprint(thumbprintHasher)
	return base64.RawURLEncoding.EncodeToString(tpBytes), err
}

func loadJSONWebKeySetByURL(jwksURL string) (keyMap map[string]interface{}, err error) {
	client := &http.Client{}

	resp, err := client.Get(jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch failed with code %v url %v", resp.StatusCode, jwksURL)
	}

	var set jose.JSONWebKeySet
	err = json.NewDecoder(resp.Body).Decode(&set)
	if err != nil {
		return nil, err
	}

	keySet := make(map[string]interface{})
	for _, key := range set.Keys {
		if _, ok := keySet[key.KeyID]; ok {
			panic("multiple keys with the same ID")
		}
		keySet[key.KeyID] = key.Key
	}
	return keySet, nil
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
		keyID, err := thumbprintKey(pub)
		if err != nil {
			panic(err)
		}
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
