package iam

import (
	"github.com/citadelium/pkg/errors"
)

type UserService interface {
	UserAccountService
	UserProfileService

	GetUserPrimaryPhoneNumber(
		callCtx CallContext,
		userID UserID,
	) (*PhoneNumber, error)

	GetUserPrimaryEmailAddress(
		callCtx CallContext,
		userID UserID,
	) (*EmailAddress, error)
}

//TODO: this does not belong to C2S service, but only in S2S service
type UserTerminalService interface {
	ListUserTerminalIDFirebaseInstanceTokens(
		ownerUserID UserID,
	) ([]TerminalIDFirebaseInstanceToken, error)
	DeleteUserTerminalFCMRegistrationToken(
		authCtx *Authorization,
		userID UserID, terminalID TerminalID, token string,
	) error
}

var (
	ErrUserPrimaryPhoneNumberConflict = errors.EntMsg("user primary phone number", "conflict")
)

type UserPhoneNumber struct {
	UserID      UserID
	PhoneNumber PhoneNumber
	IsPrimary   bool
}

// JSONV1 models

type UserPhoneNumberJSONV1 struct {
	UserID      string `json:"user_id"`
	PhoneNumber string `json:"phone_number"`
}

type UserPhoneNumberListJSONV1 struct {
	Items []UserPhoneNumberJSONV1 `json:"items"`
}

type UserEmailAddressPutRequestJSONV1 struct {
	IsPrimary bool `json:"is_primary" db:"is_primary"`
}

type UserContactListsJSONV1 struct {
	Items []UserJSONV1 `json:"items"`
}
