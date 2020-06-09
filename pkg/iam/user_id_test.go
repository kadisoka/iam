package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUserIDLimits(t *testing.T) {
	assert.Equal(t, UserID(0), UserIDZero, "zero equal")
	assert.Equal(t, false, UserID(0).IsValid(), "zero")
	assert.Equal(t, false, UserID(-1).IsValid(), "neg is invalid")
	assert.Equal(t, false, UserID(1).IsValid(), "reserved")
	assert.Equal(t, false, UserID(0xffff).IsValid(), "reserved")
	assert.Equal(t, false, UserID(0x0001000000000000).IsValid(), "over limit")
	assert.Equal(t, true, UserID(4294967296).IsValid(), "lowest normal")
	assert.Equal(t, true, UserID(4294967296).IsNormalAccount(), "lowest normal")
	assert.Equal(t, false, UserID(4294967296).IsServiceAccount(), "lowest normal")
}

func TestUserIDEncode(t *testing.T) {
	assert.Equal(t, "", UserIDZero.String(), "zero is empty")
	assert.Equal(t, "", UserID(0).String(), "zero is empty")
	assert.Equal(t, "", UserID(-1).String(), "neg is empty")
	assert.Equal(t, "", UserID(1).String(), "reserved is empty")
	assert.Equal(t, "ISv0T2000", UserID(0x10000).String(), "service account")
	assert.Equal(t, "INo0T4000000", UserID(4294967296).String(), "normal account")
	assert.Equal(t, "INo0T7zz6ya1v0x", UserID(281448076602397).String(), "normal account")
	//TODO: more cases
}

func TestUserIDDecode(t *testing.T) {
	var cases = []struct {
		encoded  string
		expected UserID
		err      error
	}{
		{"", UserIDZero, nil},
		{"ISv0T2000", UserID(0x10000), nil},
		{"INo0T4000000", UserID(4294967296), nil},
		{"INo0T7zz6ya1v0x", UserID(281448076602397), nil},
	}

	for _, c := range cases {
		uid, err := UserIDFromString(c.encoded)
		assert.Equal(t, c.err, err, "error")
		assert.Equal(t, c.expected, uid, "uid")
	}
}

//TODO: more tests
