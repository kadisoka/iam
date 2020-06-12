package jwk

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"

	"github.com/kadisoka/iam/pkg/jose/jwa"
)

type Set struct {
	Keys []Key `json:"keys"`
}

func (set *Set) AddRSAPublicKeys(publicKeys map[string]*rsa.PublicKey) error {
	for keyID, publicKey := range publicKeys {
		nBytes := publicKey.N.Bytes()
		eBytes := make([]byte, 4)
		binary.BigEndian.PutUint32(eBytes, uint32(publicKey.E))
		eBytes = bytes.TrimLeft(eBytes, "\x00")
		key := Key{
			KeyType:   jwa.KeyTypeRSA,
			Usage:     UsageSignature,
			Algorithm: jwa.AlgorithmRS256,
			KeyID:     keyID,
			N:         base64.RawURLEncoding.EncodeToString(nBytes),
			E:         base64.RawURLEncoding.EncodeToString(eBytes),
		}
		set.Keys = append(set.Keys, key)
	}
	return nil
}

func GetPublicKeysFromSetByURL(url string) (map[string]*rsa.PublicKey, error) {
	client := &http.Client{}

	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("fetch failed with code %v url %v", resp.StatusCode, url)
	}

	var set Set
	err = json.NewDecoder(resp.Body).Decode(&set)
	if err != nil {
		return nil, err
	}

	publicKeys := make(map[string]*rsa.PublicKey)
	for _, key := range set.Keys {
		switch key.KeyType {
		case jwa.KeyTypeRSA:
			if key.KeyID == "" {
				continue
			}
			var eBytes []byte
			eBytes, err = base64.RawURLEncoding.DecodeString(key.E)
			if err != nil {
				panic(err)
			}
			if len(eBytes) < 4 {
				eBytesT := make([]byte, 4)
				copy(eBytesT[4-len(eBytes):], eBytes)
				eBytes = eBytesT
			}
			var nBytes []byte
			nBytes, err = base64.RawURLEncoding.DecodeString(key.N)
			if err != nil {
				panic(err)
			}
			n := &big.Int{}
			n.SetBytes(nBytes)
			pub := &rsa.PublicKey{
				N: n,
				E: int(binary.BigEndian.Uint32(eBytes[:])),
			}
			publicKeys[key.KeyID] = pub
		}
	}
	return publicKeys, nil
}
