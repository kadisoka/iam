package iam

import (
	"github.com/citadelium/foundation/pkg/errors"
)

type Error struct {
	Msg string
	Err error
}

func (e *Error) Error() string {
	if e.Err != nil {
		if e.Msg != "" {
			return e.Msg + ": " + e.Err.Error()
		}
		return "iam: " + e.Err.Error()
	}
	return e.Msg
}

func ReqFieldErr(fieldName string, err error) error {
	return &reqFieldError{errors.Ent(fieldName, err)}
}

func ReqFieldErrMsg(fieldName, errMsg string) error {
	return &reqFieldError{errors.EntMsg(fieldName, errMsg)}
}

type reqFieldError struct {
	errors.EntityError
}

var (
	_ errors.CallError = &reqFieldError{}
)

func (e reqFieldError) CallError()        {}
func (e reqFieldError) FieldName() string { return e.EntityError.EntityIdentifier() }
