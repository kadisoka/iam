package iam

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/citadelium/pkg/errors"
	"github.com/richardlehane/crock32"
)

var (
	ErrUserIDStringInvalid        = errors.Ent("user ID string", nil)
	ErrServiceUserIDStringInvalid = errors.Ent("service user ID string", nil)
)

// UserID holds an identifier of a user account.
type UserID int64

// UserIDZero is the default value. This value is invalid for UserID.
const UserIDZero = UserID(0)

func UserIDFromPrimitiveValue(v int64) UserID { return UserID(v) }

func UserIDFromString(s string) (UserID, error) {
	if s == "" {
		return UserIDZero, nil
	}
	return userIDDecode(s)
}

func (userID UserID) IsValid() bool    { return userID > userIDReservedMax && userID <= userIDMax }
func (userID UserID) IsNotValid() bool { return !userID.IsValid() }

func (userID UserID) PrimitiveValue() int64 { return int64(userID) }

func (userID UserID) String() string {
	if userID.IsNotValid() {
		return ""
	}
	return userIDEncode(userID)
}

func (userID UserID) IsNormalAccount() bool {
	return userID.IsValid() && userID > userIDServiceMax
}

func (userID UserID) IsServiceAccount() bool {
	return userID.IsValid() && userID <= userIDServiceMax
}

func (userID UserID) MarshalText() ([]byte, error) {
	return []byte(userID.String()), nil
}

func (userID *UserID) UnmarshalText(b []byte) error {
	i, err := UserIDFromString(string(b))
	if err == nil {
		*userID = i
	}
	return err
}

func (userID UserID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + userID.String() + `"`), nil
}

func (userID *UserID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	if s == "" {
		*userID = UserIDZero
		return nil
	}
	i, err := UserIDFromString(s)
	if err == nil {
		*userID = i
	}
	return err
}

var (
	userIDEncodingOnce sync.Once

	userIDMax         UserID = userIDV1Max
	userIDServiceMax  UserID = userIDV1ServiceMax
	userIDReservedMax UserID = userIDV1ReservedMax

	userIDEncode func(UserID) string          = userIDV1Encode
	userIDDecode func(string) (UserID, error) = userIDV1Decode
)

func UseUserIDV0Enconding() {
	userIDEncodingOnce.Do(func() {
		userIDMax = userIDV0Max
		userIDServiceMax = userIDV0ServiceMax
		userIDReservedMax = userIDV0ReservedMax
		userIDEncode = userIDV0Encode
		userIDDecode = userIDV0Decode
	})
}

const (
	userIDV1Max           = 0x0000ffffffffffff
	userIDV1ReservedMax   = 0x000000000000ffff
	userIDV1ServiceMax    = 0x00000000ffffffff
	userIDV1Prefix        = "INo0T"
	userIDV1ServicePrefix = "ISv0T"
)

func userIDV1Encode(userID UserID) string {
	var prefix string
	if userID.IsServiceAccount() {
		prefix = userIDV1ServicePrefix
	} else {
		prefix = userIDV1Prefix
	}
	return prefix + crock32.Encode(uint64(userID))
}

func userIDV1Decode(s string) (UserID, error) {
	isService := strings.HasPrefix(s, userIDV1ServicePrefix)
	if isService {
		s = strings.TrimPrefix(s, userIDV1ServicePrefix)
	} else {
		s = strings.TrimPrefix(s, userIDV1Prefix)
	}

	i, err := crock32.Decode(s)
	if err != nil {
		return UserIDZero, errors.Arg("", err)
	}
	// To ensure we can safely treat it as signed
	if i > uint64(0x7fffffffffffffff) {
		return UserIDZero, errors.ArgMsg("", "overflow")
	}

	if isService {
		if i > userIDV1ServiceMax {
			return UserIDZero, errors.Arg("", nil)
		}
	} else {
		if i != 0 && i <= userIDV1ServiceMax {
			return UserIDZero, errors.Arg("", nil)
		}
	}

	return UserID(i), nil
}

const (
	userIDV0Max = 0x0000ffffffffffff

	// userIDV0ReservedMax is maximum value for reserved user IDs. IDs within
	// this range should never be considered as valid user IDs in client
	// applications.
	userIDV0ReservedMax = 0x00000000000fffff

	// userIDV0ServiceMax is a constant which we use to separate service user IDs
	// and normal user IDs.
	//
	// We are reserving user IDs up to this value. We will use these user ID for
	// various purpose in the future. Possible usage: service applications, bots,
	// service notifications.
	userIDV0ServiceMax = 0x00000003ffffffff

	// userIDV0ServicePrefix is a prefix we use to differentiate normal
	// user (human-representing) account and service user account.
	userIDV0ServicePrefix = "is-0x"

	// userIDV0Prefix is the prefix for normal users.
	userIDV0Prefix = "i-0x"

	userIDV0EncodingRadix = 16
)

func userIDV0Encode(userID UserID) string {
	var prefix string
	if userID.IsServiceAccount() {
		prefix = userIDV0ServicePrefix
	} else {
		prefix = userIDV0Prefix
	}
	return prefix + fmt.Sprintf("%016x", userID.PrimitiveValue())
}

func userIDV0Decode(s string) (UserID, error) {
	isService := strings.HasPrefix(s, userIDV0ServicePrefix)
	if isService {
		s = strings.TrimPrefix(s, userIDV0ServicePrefix)
	} else {
		s = strings.TrimPrefix(s, userIDV0Prefix)
	}

	i, err := strconv.ParseInt(s, userIDV0EncodingRadix, 64)
	if err != nil {
		return UserIDZero, errors.Arg("", err)
	}

	if isService {
		if i > userIDV0ServiceMax {
			return UserIDZero, errors.Arg("", nil)
		}
	} else {
		if i != 0 && i <= userIDV0ServiceMax {
			return UserIDZero, errors.Arg("", nil)
		}
	}

	return UserID(i), nil
}
