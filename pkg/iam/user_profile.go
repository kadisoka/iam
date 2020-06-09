package iam

import (
	iampb "github.com/rez-go/crux-apis/crux/iam/v1"
)

type UserProfileService interface {
	GetUserInfoV1(
		callCtx CallContext,
		userID UserID,
	) (*iampb.UserInfoData, error)
	GetUserBaseProfile(
		callCtx CallContext,
		userID UserID,
	) (*UserBaseProfile, error)
	UpdateUserProfile(
		callCtx CallContext,
		userID UserID,
		input UserProfileUpdateInput,
	) (updated bool, err error)
}

type UserBaseProfile struct {
	ID              UserID
	DisplayName     string
	ProfileImageURL string
	IsDeleted       bool
}

type UserProfileUpdateInput struct {
	DisplayName     *string
	ProfileImageURL *string
}

// JSONV1 models

type UserJSONV1 struct {
	ID              string `json:"id"`
	DisplayName     string `json:"display_name"`
	ProfileImageURL string `json:"profile_image_url"`
	PhoneNumber     string `json:"phone_number,omitempty"`
	EmailAddress    string `json:"email_address,omitempty"`
}

func UserJSONV1FromBaseProfile(model *UserBaseProfile) *UserJSONV1 {
	if model == nil {
		return nil
	}
	return &UserJSONV1{
		ID:              model.ID.String(),
		DisplayName:     model.DisplayName,
		ProfileImageURL: model.ProfileImageURL,
	}
}
