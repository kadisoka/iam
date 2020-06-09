package pnv10n

import (
	"errors"
)

var (
	ErrVerificationCodeMismatch = errors.New("code mismatch")
	ErrVerificationCodeExpired  = errors.New("code expired")
)

type ConfigurationError struct {
	Err error
}

func (err ConfigurationError) Error() string {
	const baseMsg = "configuration error"
	if err.Err != nil {
		return baseMsg + ": " + err.Err.Error()
	}
	return baseMsg
}

type GatewayError struct {
	Err error
}

func (err GatewayError) Error() string {
	const baseMsg = "gateway error"
	if err.Err != nil {
		return baseMsg + ": " + err.Err.Error()
	}
	return baseMsg
}

type InvalidPhoneNumberError struct {
	Err error
}

func (err InvalidPhoneNumberError) Error() string {
	if err.Err != nil {
		return "invalid phone number: " + err.Err.Error()
	}
	return "invalid phone number"
}

type PhoneNumberRegionNotSupportedError struct {
	Err error
}

func (err PhoneNumberRegionNotSupportedError) Error() string {
	if err.Err != nil {
		return "phone number region not supported: " + err.Err.Error()
	}
	return "phone number region not supported"
}
