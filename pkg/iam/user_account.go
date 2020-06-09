package iam

type UserAccountService interface {
	// IsUserIDRegistered is to check if the user ID is trully registered to
	// system.
	IsUserIDRegistered(userID UserID) bool

	UserAccountStateService

	// DeleteUserAccount deletes an user account based identfied by userIDToDelete.
	DeleteUserAccount(
		callCtx CallContext,
		userIDToDelete UserID,
		input UserAccountDeleteInput,
	) (deleted bool, err error)
}

type UserAccountStateService interface {
	// GetUserAccountState checks if the provided user ID is valid and whether
	// the account is deleted.
	//
	// This method returns nil if the userID is not referencing to any valid
	// user account.
	GetUserAccountState(
		/*callCtx CallContext,*/ //TODO: call context
		userID UserID,
	) (*UserAccountState, error)
}

type UserAccountState struct {
	Deleted bool
}

func (uaState UserAccountState) IsAccountActive() bool {
	return !uaState.Deleted
}

//TODO: make this struct instances connect to IAM server and manage
// synchronization of user account states.
type UserAccountStateServiceClientCore struct {
}

func (uaStateSvcClient *UserAccountStateServiceClientCore) GetUserAccountState(
	userID UserID,
) (*UserAccountState, error) {
	return &UserAccountState{false}, nil
}

//TODO: reason and comment
type UserAccountDeleteInput struct {
	DeletionNotes string
}
