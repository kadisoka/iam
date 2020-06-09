package iam

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/citadelium/foundation/pkg/errors"
	"github.com/richardlehane/crock32"
)

// ClientID is the primary way to identify a client within the system.
//
// Currently we are using 32bit integer to store it. This should be enough
// for most use cases. This might change if there's any real case needing
// us to use type with higher capacity.
type ClientID int32

// ClientIDZero is the default value for a ClientID. ClientIDZero never
// represent valid client.
const ClientIDZero = ClientID(0)

func ClientIDFromString(s string) (ClientID, error) {
	if s == "" {
		return ClientIDZero, nil
	}
	cid, err := clientIDDecode(s)
	if err != nil {
		return ClientIDZero, err
	}
	if cid.IsNotValid() {
		return ClientIDZero, errors.Msg("unexpected")
	}
	return cid, nil
}

func (clientID ClientID) String() string {
	if clientID.IsNotValid() {
		return ""
	}
	return clientIDEncode(clientID)
}

func (clientID ClientID) IsValid() bool {
	return clientID.validVersion() &&
		clientID.validInstance() &&
		clientID.validType()
}
func (clientID ClientID) IsNotValid() bool {
	return !clientID.IsValid()
}

func (clientID ClientID) IsConfidential() bool {
	switch clientID.typeInfo() {
	case clientIDTypeService, clientIDTypeConfidentialUserAgent:
		return true
	}
	return false
}

func (clientID ClientID) IsPublic() bool {
	switch clientID.typeInfo() {
	case clientIDTypePublicUserAgent:
		return true
	}
	return false
}

func (clientID ClientID) IsUserAgent() bool {
	switch clientID.typeInfo() {
	case clientIDTypePublicUserAgent, clientIDTypeConfidentialUserAgent:
		return true
	}
	return false
}

func (clientID ClientID) IsService() bool {
	switch clientID.typeInfo() {
	case clientIDTypeService:
		return true
	}
	return false
}

func (clientID ClientID) validVersion() bool {
	return (uint32(clientID) & clientIDMaskVersion) == 0
}
func (clientID ClientID) typeInfo() uint32 {
	return (uint32(clientID) & clientIDMaskType) >> clientIDMaskTypeShift
}
func (clientID ClientID) validType() bool {
	switch clientID.typeInfo() {
	case clientIDTypeService, clientIDTypePublicUserAgent, clientIDTypeConfidentialUserAgent:
		return true
	}
	return false
}
func (clientID ClientID) validInstance() bool {
	return (uint32(clientID) & clientIDMaskInstance) != 0
}

var (
	clientIDEncodingOnce sync.Once

	clientIDEncode func(ClientID) string          = clientIDV1Encode
	clientIDDecode func(string) (ClientID, error) = clientIDV1Decode
)

func UseClientIDV0Enconding() {
	clientIDEncodingOnce.Do(func() {
		clientIDEncode = clientIDV0Encode
		clientIDDecode = clientIDV0Decode
	})
}

//TODO: OAuth spec mentioned about confidential client type. Find out more about it.
type clientType string

func (clientTyp clientType) String() string { return string(clientTyp) }

const (
	// Background services etc. Those which don't represent users.
	clientTypeService clientType = "service"
	// User agents. Those which represents users. Actions are associated to
	// the user.
	//
	// This type means that the applications are unable to secure their client
	// credentials.
	clientTypeUserAgent clientType = "user-agent"
	// User agents which able to secure their client credentials. This works
	// through 3-legged authorization.
	//
	// Actions are associated to the user.
	clientTypeSecureUserAgent clientType = "secure-user-agent"
)

const (
	clientIDTypeService               = 1
	clientIDTypePublicUserAgent       = 2
	clientIDTypeConfidentialUserAgent = 3
)

const (
	clientIDMax              = 0x0fffffff
	clientIDMaskInstance     = 0x00ffffff
	clientIDMaskType         = 0x0f000000
	clientIDMaskTypeShift    = 24
	clientIDMaskVersion      = 0x70000000
	clientIDMaskVersionShift = 8
)

const (
	clientIDV1PrefixVersion                   = "0T"
	clientIDV1PrefixTypeLen                   = 3
	clientIDV1PrefixTypeService               = "CSv"
	clientIDV1PrefixTypePublicUserAgent       = "CUA"
	clientIDV1PrefixTypeConfidentialUserAgent = "CCU"
)

func clientIDV1Encode(clientID ClientID) string {
	var prefix string
	switch clientID.typeInfo() {
	case clientIDTypeService:
		prefix = clientIDV1PrefixTypeService
	case clientIDTypePublicUserAgent:
		prefix = clientIDV1PrefixTypePublicUserAgent
	case clientIDTypeConfidentialUserAgent:
		prefix = clientIDV1PrefixTypeConfidentialUserAgent
	default:
		panic("Unsupported client type")
	}
	return prefix + clientIDV1PrefixVersion + crock32.Encode(uint64(clientID))
}

func clientIDV1Decode(s string) (ClientID, error) {
	if len(s) <= clientIDV1PrefixTypeLen+len(clientIDV1PrefixVersion) {
		return ClientIDZero, errors.Arg("", errors.Ent("length", nil))
	}

	var typeInfo uint32
	typePrefix := s[:clientIDV1PrefixTypeLen]
	switch typePrefix {
	case clientIDV1PrefixTypeService:
		typeInfo = clientIDTypeService
	case clientIDV1PrefixTypePublicUserAgent:
		typeInfo = clientIDTypePublicUserAgent
	case clientIDV1PrefixTypeConfidentialUserAgent:
		typeInfo = clientIDTypeConfidentialUserAgent
	default:
		return ClientIDZero, errors.Arg("", errors.Ent("type", nil))
	}

	stub := s[clientIDV1PrefixTypeLen:]
	if stub[:len(clientIDV1PrefixVersion)] != clientIDV1PrefixVersion {
		return ClientIDZero, errors.Arg("", errors.Ent("version", nil))
	}

	instIDStr := stub[len(clientIDV1PrefixVersion):]
	instIDU64, err := crock32.Decode(instIDStr)
	if err != nil {
		return ClientIDZero, errors.Arg("", err)
	}
	if instIDU64 > clientIDMax {
		return ClientIDZero, errors.ArgMsg("", "overflow")
	}
	cid := ClientID(instIDU64)
	if typeInfo != cid.typeInfo() {
		return ClientIDZero, errors.Arg("", nil)
	}
	return cid, nil
}

const (
	clientIDV0Prefix = "cl-0x"
	clientIDV0Shift  = 8
)

func clientIDV0Encode(clientID ClientID) string {
	return fmt.Sprintf("%s%08x", clientIDV0Prefix, int32(clientID)<<clientIDV0Shift)
}

func clientIDV0Decode(s string) (ClientID, error) {
	s = strings.TrimPrefix(s, clientIDV0Prefix)
	i, err := strconv.ParseInt(s, 16, 32)
	return ClientID(i >> clientIDV0Shift), err
}

// GenerateClientID generates a new ClientID. Note that this function is
// not consulting any database. To ensure that the generated ClientID is
// unique, check the client database.
func GenerateClientID(clientTyp string) ClientID {
	var typeInfo uint32
	switch clientType(clientTyp) {
	case clientTypeService:
		typeInfo = clientIDTypeService
	case clientTypeUserAgent:
		typeInfo = clientIDTypePublicUserAgent
	case clientTypeSecureUserAgent:
		typeInfo = clientIDTypeConfidentialUserAgent
	default:
		panic("Unsupported client app type")
	}
	instIDBytes := make([]byte, 4)
	_, err := rand.Read(instIDBytes[1:])
	if err != nil {
		panic(err)
	}
	//TODO: reserve some ranges (?)
	instID := binary.BigEndian.Uint32(instIDBytes) & 0x00ffffff
	return ClientID((typeInfo << clientIDMaskTypeShift) | instID)
}
