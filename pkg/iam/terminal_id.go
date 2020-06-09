package iam

import (
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/citadelium/foundation/pkg/errors"
	"github.com/richardlehane/crock32"
)

type TerminalID int64

const TerminalIDZero = TerminalID(0)

func TerminalIDFromString(s string) (TerminalID, error) {
	if s == "" {
		return TerminalIDZero, nil
	}
	tid, err := terminalIDDecode(s)
	if err != nil {
		return TerminalIDZero, err
	}
	if tid.IsNotValid() {
		return TerminalIDZero, errors.Msg("unexpeted")
	}
	return tid, nil
}

func (terminalID TerminalID) String() string {
	if terminalID.IsNotValid() {
		return ""
	}
	return terminalIDEncode(terminalID)
}

func (terminalID TerminalID) IsValid() bool {
	return (terminalID&terminalInstanceIDMask) > 0 &&
		terminalID.ClientID().IsValid()
}

func (terminalID TerminalID) IsNotValid() bool {
	return !terminalID.IsValid()
}

func (terminalID TerminalID) ClientID() ClientID {
	return ClientID(int64(terminalID) >> terminalClientIDShift)
}

func (terminalID TerminalID) InstanceID() int32 {
	return int32(terminalID & terminalInstanceIDMask)
}

func (terminalID TerminalID) MarshalText() ([]byte, error) {
	return []byte(terminalID.String()), nil
}

func (terminalID *TerminalID) UnmarshalText(b []byte) error {
	i, err := TerminalIDFromString(string(b))
	if err == nil {
		*terminalID = i
	}
	return err
}

func (terminalID TerminalID) MarshalJSON() ([]byte, error) {
	return []byte(`"` + terminalID.String() + `"`), nil
}

func (terminalID *TerminalID) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	i, err := TerminalIDFromString(s)
	if err == nil {
		*terminalID = i
	}
	return err
}

const (
	terminalInstanceIDMask = 0x00000000ffffffff
	terminalIDMax          = 0x7fffffffffffffff
	terminalClientIDShift  = 32
)

var (
	terminalIDEncodingOnce sync.Once

	terminalIDEncode func(TerminalID) string          = terminalIDV1Encode
	terminalIDDecode func(string) (TerminalID, error) = terminalIDV1Decode
)

func UseTerminalIDV0Enconding() {
	terminalIDEncodingOnce.Do(func() {
		terminalIDEncode = terminalIDV0Encode
		terminalIDDecode = terminalIDV0Decode
	})
}

const (
	terminalIDV1Prefix = "TZZ0T"
)

func terminalIDV1Encode(tid TerminalID) string {
	return terminalIDV1Prefix + crock32.Encode(uint64(tid))
}

func terminalIDV1Decode(s string) (TerminalID, error) {
	if len(s) <= len(terminalIDV1Prefix) {
		return TerminalIDZero, errors.Arg("", errors.Ent("length", nil))
	}
	pfx := s[:len(terminalIDV1Prefix)]
	if pfx != terminalIDV1Prefix {
		return TerminalIDZero, errors.Arg("", errors.Ent("prefix", nil))
	}
	instIDStr := s[len(pfx):]
	instIDU64, err := crock32.Decode(instIDStr)
	if err != nil {
		return TerminalIDZero, errors.Arg("", err)
	}
	if instIDU64 > terminalIDMax {
		return TerminalIDZero, errors.ArgMsg("", "overflow")
	}
	return TerminalID(instIDU64), nil
}

const (
	terminalIDV0Prefix = "tl-0x"
)

func terminalIDV0Encode(tid TerminalID) string {
	return fmt.Sprintf("%s%016x", terminalIDV0Prefix, int64(tid))
}

func terminalIDV0Decode(s string) (TerminalID, error) {
	s = strings.TrimPrefix(s, terminalIDV0Prefix)
	i, err := strconv.ParseInt(s, 16, 64)
	return TerminalID(i), err
}
