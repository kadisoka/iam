package pnv10n

import (
	"time"

	"github.com/citadelium/iam/pkg/iam"
)

type VerificationMethod int

const (
	VerificationMethodUnspecified VerificationMethod = iota
	VerificationMethodNone
	VerificationMethodSMS
)

func VerificationMethodFromString(str string) VerificationMethod {
	switch str {
	case "none":
		return VerificationMethodNone
	case "sms":
		return VerificationMethodSMS
	}
	return VerificationMethodUnspecified
}

//TODO: make this private
type verificationDBModel struct {
	ID                     int64           `db:"id"`
	CountryCode            int32           `db:"country_code"`
	NationalNumber         int64           `db:"national_number"`
	Code                   string          `db:"code"`
	CodeExpiry             *time.Time      `db:"code_expiry"`
	AttemptsRemaining      int16           `db:"attempts_remaining"`
	CreationTime           time.Time       `db:"creation_time"`
	CreationUserID         iam.UserID      `db:"creation_user_id"`
	CreationTerminalID     iam.TerminalID  `db:"creation_terminal_id"`
	ConfirmationTime       *time.Time      `db:"confirmation_time"`
	ConfirmationUserID     *iam.UserID     `db:"confirmation_user_id"`
	ConfirmationTerminalID *iam.TerminalID `db:"confirmation_terminal_id"`
}
