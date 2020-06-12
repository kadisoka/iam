package iam

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/kadisoka/foundation/pkg/errors"
	"github.com/richardlehane/crock32"
)

type AuthorizationID struct {
	TerminalID TerminalID
	InstanceID AuthorizationInstanceID
}

var AuthorizationIDZero = AuthorizationID{}

func AuthorizationIDFromString(s string) (AuthorizationID, error) {
	if s == "" {
		return AuthorizationIDZero, nil
	}
	authzID, err := authorizationIDDecode(s)
	if err != nil {
		return AuthorizationIDZero, err
	}
	if authzID.IsNotValid() {
		return AuthorizationIDZero, errors.Msg("unexpected")
	}
	return authzID, nil
}

func (authzID AuthorizationID) ClientID() ClientID {
	return authzID.TerminalID.ClientID()
}

func (authzID AuthorizationID) IsValid() bool {
	return authzID.TerminalID.IsValid() &&
		authzID.InstanceID > 0
}

func (authzID AuthorizationID) IsNotValid() bool {
	return !authzID.IsValid()
}

func (authzID AuthorizationID) String() string {
	if authzID.IsNotValid() {
		return ""
	}
	return authorizationIDEncode(authzID)
}

func (authzID AuthorizationID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + authzID.String() + `"`), nil
}

func (authzID *AuthorizationID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	i, err := AuthorizationIDFromString(s)
	if err == nil {
		*authzID = i
	}
	return err
}

var (
	authorizationIDEncodingOnce sync.Once

	authorizationIDEncode func(AuthorizationID) string          = authorizationIDV1Encode
	authorizationIDDecode func(string) (AuthorizationID, error) = authorizationIDV1Decode
)

func UseAuthorizationIDV0Enconding() {
	authorizationIDEncodingOnce.Do(func() {
		authorizationIDEncode = authorizationIDV0Encode
		authorizationIDDecode = authorizationIDV0Decode
	})
}

const authorizationIDV1Prefix = "AzZZ0T"

func authorizationIDV1Encode(authzID AuthorizationID) string {
	return authorizationIDV1Prefix +
		crock32.Encode(uint64(authzID.TerminalID)) + "-" + crock32.Encode(uint64(authzID.InstanceID))
}

func authorizationIDV1Decode(s string) (AuthorizationID, error) {
	if len(s) <= len(authorizationIDV1Prefix) {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("length", nil))
	}
	pfx := s[:len(authorizationIDV1Prefix)]
	if pfx != authorizationIDV1Prefix {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("prefix", nil))
	}
	dataPartStr := s[len(pfx):]
	dataParts := strings.Split(dataPartStr, "-")
	if len(dataParts) < 2 {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("data", nil))
	}

	termIDU64, err := crock32.Decode(dataParts[0])
	if err != nil {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("terminal", err))
	}
	if termIDU64 > terminalIDMax {
		return AuthorizationIDZero, errors.Arg("", errors.EntMsg("terminal", "overflow"))
	}
	termID := TerminalID(termIDU64)
	if termID.IsNotValid() {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("terminal", nil))
	}

	instIDU64, err := crock32.Decode(dataParts[1])
	if err != nil {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("instance", err))
	}
	if instIDU64 > 0x7fffffffffffffff {
		return AuthorizationIDZero, errors.Arg("", errors.EntMsg("instance", "overflow"))
	}
	instID := AuthorizationInstanceID(instIDU64)
	if instID.IsNotValid() {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("terminal", nil))
	}

	return AuthorizationID{
		TerminalID: termID,
		InstanceID: instID,
	}, nil
}

const authorizationIDV0Prefix = "az-0x"

func authorizationIDV0Encode(authzID AuthorizationID) string {
	return fmt.Sprintf("%s%016x-%016x",
		authorizationIDV0Prefix,
		int64(authzID.TerminalID),
		int64(authzID.InstanceID))
}

func authorizationIDV0Decode(s string) (AuthorizationID, error) {
	s = strings.TrimPrefix(s, "taz-0x")
	s = strings.TrimPrefix(s, authorizationIDV0Prefix)
	dataParts := strings.Split(s, "-")
	if len(dataParts) < 2 {
		return AuthorizationIDZero, errors.Arg("", nil)
	}
	terminalID, err := strconv.ParseInt(dataParts[0], 16, 64)
	if err != nil {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("terminal", err))
	}
	instanceID, err := strconv.ParseInt(dataParts[1], 16, 64)
	if err != nil {
		return AuthorizationIDZero, errors.Arg("", errors.Ent("instance", err))
	}
	return AuthorizationID{
		TerminalID: TerminalID(terminalID),
		InstanceID: AuthorizationInstanceID(instanceID),
	}, nil
}

// AuthorizationInstanceID is a type which holds an instance ID of an
// authorization.
//
//TODO: use 32bit integer instead as we are scoped within terminal ID
type AuthorizationInstanceID int64

const AuthorizationInstanceIDZero = AuthorizationInstanceID(0)

func (authInstID AuthorizationInstanceID) IsValid() bool {
	return authInstID > 0
}
func (authInstID AuthorizationInstanceID) IsNotValid() bool {
	return !authInstID.IsValid()
}
