package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClientIDLimits(t *testing.T) {
	assert.Equal(t, ClientID(0), ClientIDZero)
	assert.Equal(t, false, ClientID(0).IsValid())
	assert.Equal(t, false, ClientID(-1).IsValid())
	assert.Equal(t, false, ClientID(1).IsValid())
	assert.Equal(t, false, ClientID(0xffff).IsValid())
	assert.Equal(t, false, ClientID(0xffffff).IsValid())
	assert.Equal(t, false, ClientID(0x7fffffff).IsValid())
	assert.Equal(t, false, ClientID(0x01000000).IsValid())
	assert.Equal(t, true, ClientID(0x01000001).IsValid())
	assert.Equal(t, true, ClientID(0x01ffffff).IsValid())
}

func TestClientIDEncode(t *testing.T) {
	assert.Equal(t, "", ClientIDZero.String())
	assert.Equal(t, "", ClientID(0).String())
	assert.Equal(t, "", ClientID(-1).String())
	assert.Equal(t, "", ClientID(1).String())
	assert.Equal(t, "CSv0Tg0001", ClientID(0x01000001).String())
	assert.Equal(t, "CSv0Tzzzzz", ClientID(0x01ffffff).String())
	assert.Equal(t, "CUA0T100001", ClientID(0x02000001).String())
	assert.Equal(t, "CUA0T1fzzzz", ClientID(0x02ffffff).String())
	assert.Equal(t, "CCU0T1g0001", ClientID(0x03000001).String())
	assert.Equal(t, "CCU0T1zzzzz", ClientID(0x03ffffff).String())
	assert.Equal(t, "CSv0Tmv42m", ClientID(21860436).String())
	assert.Equal(t, "CUA0T1e27bq", ClientID(48307575).String())
	assert.Equal(t, "CUA0T11xq3e", ClientID(35576942).String())
	assert.Equal(t, "CCU0T1gp34z", ClientID(51055775).String())
	//TODO: more cases
}

func TestClientIDDecode(t *testing.T) {
	var cases = []struct {
		encoded  string
		expected ClientID
		err      error
	}{
		{"", ClientIDZero, nil},
		{"CSv0Tmv42m", ClientID(21860436), nil},
		{"CUA0T1e27bq", ClientID(48307575), nil},
		{"CUA0T11xq3e", ClientID(35576942), nil},
		{"CCU0T1gp34z", ClientID(51055775), nil},
	}

	for cidx, c := range cases {
		uid, err := ClientIDFromString(c.encoded)
		assert.Equal(t, c.err, err, "case index %v: %v", cidx, err)
		assert.Equal(t, c.expected, uid, "case index %v", cidx)
	}
}

//TODO: more tests
