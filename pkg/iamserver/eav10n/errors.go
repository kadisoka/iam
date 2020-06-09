package eav10n

import (
	"errors"
)

var (
	ErrVerificationCodeMismatch = errors.New("code mismatch")
	ErrVerificationCodeExpired  = errors.New("code expired")
)

type InvalidEmailAddressError struct {
	Err error
}

func (err InvalidEmailAddressError) Error() string {
	if err.Err != nil {
		return "invalid email address: " + err.Err.Error()
	}
	return "invalid email address"
}
