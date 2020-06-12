package iamserver

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/kadisoka/foundation/pkg/errors"
	iampb "github.com/rez-go/crux-apis/crux/iam/v1"
	"golang.org/x/crypto/blake2b"

	"github.com/kadisoka/iam/pkg/iam"
)

func (core *Core) GetUserBaseProfile(
	callCtx iam.CallContext,
	userID iam.UserID,
) (*iam.UserBaseProfile, error) {
	if callCtx == nil {
		return nil, errors.ArgMsg("callCtx", "missing")
	}
	//TODO(exa): ensure that the context user has the privilege

	var user iam.UserBaseProfile
	var displayName *string
	var profileImageURL *string

	err := core.db.
		QueryRow(
			`SELECT ua.id, `+
				`CASE WHEN ua.deletion_time IS NULL THEN false ELSE true END AS is_deleted, `+
				`udn.display_name, upiu.profile_image_url `+
				`FROM users AS ua `+
				`LEFT JOIN user_display_names udn ON udn.user_id = ua.id AND udn.deletion_time IS NULL `+
				`LEFT JOIN user_profile_image_urls upiu ON upiu.user_id = ua.id AND upiu.deletion_time IS NULL `+
				`WHERE ua.id = $1`,
			userID).
		Scan(&user.ID, &user.IsDeleted, &displayName, &profileImageURL)
	if err != nil {
		switch err {
		case sql.ErrNoRows:
			return nil, nil
		default:
			return nil, err
		}
	}

	if displayName != nil {
		user.DisplayName = *displayName
	}
	if profileImageURL != nil {
		user.ProfileImageURL = *profileImageURL
	}

	return &user, nil
}

// GetUserAccountState retrieves the state of an user account. It includes
// the existence of the ID, and wether the account has been deleted.
//
// If it's required only to determine the existence of the ID,
// IsUserIDRegistered is generally more efficient.
func (core *Core) GetUserAccountState(
	id iam.UserID,
) (*iam.UserAccountState, error) {
	idRegistered := false
	idRegisteredCacheHit := false
	accountDeleted := false
	accountDeletedCacheHit := false
	// Look up for an user ID in the cache.
	if _, idRegistered = core.registeredUserIDCache.Get(id); idRegistered {
		// User ID is positively registered.
		idRegisteredCacheHit = true
	}

	// Look up in the cache
	if _, accountDeleted := core.deletedUserAccountIDCache.Get(id); accountDeleted {
		// Account is positively deleted
		accountDeletedCacheHit = true
	}

	if idRegisteredCacheHit && accountDeletedCacheHit {
		if !idRegistered {
			return nil, nil
		}
		return &iam.UserAccountState{
			Deleted: accountDeleted,
		}, nil
	}

	var err error
	idRegistered, accountDeleted, err = core.
		getUserAccountState(id)
	if err != nil {
		return nil, err
	}

	if !idRegisteredCacheHit && idRegistered {
		core.registeredUserIDCache.Add(id, nil)
	}
	if !accountDeletedCacheHit && accountDeleted {
		core.deletedUserAccountIDCache.Add(id, nil)
	}

	if !idRegistered {
		return nil, nil
	}
	return &iam.UserAccountState{
		Deleted: accountDeleted,
	}, nil
}

// IsUserIDRegistered is used to determine that a user ID has been registered.
// It's not checking if the account is active or not.
//
// This function is generally cheap if the user ID has been registered.
func (core *Core) IsUserIDRegistered(id iam.UserID) bool {
	// Look up for an user ID in the cache.
	if _, idRegistered := core.registeredUserIDCache.Get(id); idRegistered {
		return true
	}

	idRegistered, _, err := core.
		getUserAccountState(id)
	if err != nil {
		panic(err)
	}

	if idRegistered {
		core.registeredUserIDCache.Add(id, nil)
	}

	return idRegistered
}

func (core *Core) getUserAccountState(
	id iam.UserID,
) (idRegistered, accountDeleted bool, err error) {
	err = core.db.
		QueryRow(
			`SELECT CASE WHEN deletion_time IS NULL THEN false ELSE true END `+
				`FROM users WHERE id = $1`,
			id).
		Scan(&accountDeleted)
	if err == sql.ErrNoRows {
		return false, false, nil
	}
	if err != nil {
		return false, false, err
	}

	return true, accountDeleted, nil
}

func (core *Core) DeleteUserAccount(
	callCtx iam.CallContext,
	userID iam.UserID,
	input iam.UserAccountDeleteInput,
) (deleted bool, err error) {
	if callCtx == nil {
		return false, nil
	}
	authCtx := callCtx.Authorization()
	if !authCtx.IsUserContext() || authCtx.UserID != userID {
		return false, nil
	}

	err = doTx(core.db, func(dbTx *sqlx.Tx) error {
		xres, txErr := dbTx.Exec(
			"UPDATE users "+
				"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2, deletion_notes = $3 "+
				"WHERE id = $1 AND deletion_time IS NULL",
			authCtx.UserID, authCtx.TerminalID(), input.DeletionNotes)
		if txErr != nil {
			return txErr
		}
		n, txErr := xres.RowsAffected()
		if txErr != nil {
			return txErr
		}
		deleted = n == 1

		if txErr == nil {
			_, txErr = dbTx.Exec(
				"UPDATE user_phone_numbers "+
					"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2 "+
					"WHERE user_id = $1 AND deletion_time IS NULL",
				authCtx.UserID)
		}

		if txErr == nil {
			_, txErr = dbTx.Exec(
				"UPDATE user_profile_image_urls "+
					"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2 "+
					"WHERE user_id = $1 AND deletion_time IS NULL",
				authCtx.UserID, authCtx.TerminalID())
		}

		return txErr
	})
	if err != nil {
		return false, err
	}

	//TODO: update caches, emit events if there's any changes

	return deleted, nil
}

func (core *Core) UpdateUserProfile(
	callCtx iam.CallContext,
	userID iam.UserID,
	input iam.UserProfileUpdateInput,
) (updated bool, err error) {
	if callCtx == nil {
		return false, nil
	}
	authCtx := callCtx.Authorization()
	if !authCtx.IsUserContext() || authCtx.UserID != userID {
		return false, nil
	}

	if input.ProfileImageURL != nil && *input.ProfileImageURL != "" && !core.IsUserProfileImageURLAllowed(*input.ProfileImageURL) {
		return false, errors.ArgMsg("input.ProfileImageURL", "unsupported")
	}

	//TODO: detect changes
	err = doTx(core.db, func(dbTx *sqlx.Tx) error {
		if input.DisplayName != nil {
			_, txErr := dbTx.Exec(
				"UPDATE user_display_names "+
					"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2 "+
					"WHERE user_id = $1 AND deletion_time IS NULL",
				authCtx.UserID, authCtx.TerminalID())
			if txErr != nil {
				return errors.Wrap("mark current display name as deleted", txErr)
			}
			displayName := strings.TrimSpace(*input.DisplayName)
			if displayName != "" {
				_, txErr = dbTx.Exec(
					"INSERT INTO user_display_names "+
						"(user_id, display_name, creation_user_id, creation_terminal_id) VALUES "+
						"($1, $2, $3, $4)",
					authCtx.UserID, displayName, authCtx.UserID, authCtx.TerminalID())
				if txErr != nil {
					return errors.Wrap("insert new display name", txErr)
				}
			}
		}
		if input.ProfileImageURL != nil {
			_, txErr := dbTx.Exec(
				"UPDATE user_profile_image_urls "+
					"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2 "+
					"WHERE user_id = $1 AND deletion_time IS NULL",
				authCtx.UserID, authCtx.TerminalID())
			if txErr != nil {
				return errors.Wrap("mark current profile image URL as deleted", txErr)
			}
			if *input.ProfileImageURL != "" {
				_, txErr = dbTx.Exec(
					"INSERT INTO user_profile_image_urls "+
						"(user_id, profile_image_url, creation_user_id, creation_terminal_id) VALUES "+
						"($1, $2, $3, $4)",
					authCtx.UserID, input.ProfileImageURL, authCtx.UserID, authCtx.TerminalID())
				if txErr != nil {
					return errors.Wrap("insert new profile image URL", txErr)
				}
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}

	//TODO: update caches, emit events only if there's any changes

	return updated, nil
}

func (core *Core) SetUserProfileImageURL(
	callCtx iam.CallContext,
	userID iam.UserID,
	profileImageURL string,
) error {
	authCtx := callCtx.Authorization()
	// Change this if we want to allow service client to update a user's profile
	// (we'll need a better access control for service clients)
	if !authCtx.IsUserContext() {
		return iam.ErrUserContextRequired
	}
	// Don't allow changing other user's for now
	if authCtx.UserID != userID {
		return iam.ErrContextUserNotAllowedToPerformActionOnResource
	}
	if profileImageURL != "" && !core.IsUserProfileImageURLAllowed(profileImageURL) {
		return errors.ArgMsg("profileImageURL", "unsupported")
	}

	return doTx(core.db, func(dbTx *sqlx.Tx) error {
		_, txErr := dbTx.Exec(
			"UPDATE user_profile_image_urls "+
				"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2 "+
				"WHERE user_id = $1 AND deletion_time IS NULL",
			authCtx.UserID, authCtx.TerminalID())
		if txErr != nil {
			return errors.Wrap("mark current profile image URL as deleted", txErr)
		}
		if profileImageURL != "" {
			_, txErr = dbTx.Exec(
				"INSERT INTO user_profile_image_urls "+
					"(user_id, profile_image_url, creation_user_id, creation_terminal_id) VALUES "+
					"($1, $2, $3, $4)",
				authCtx.UserID, profileImageURL, authCtx.UserID, authCtx.TerminalID())
			if txErr != nil {
				return errors.Wrap("insert new profile image URL", txErr)
			}
		}
		return nil
	})
}

func (core *Core) GetUserInfoV1(
	callCtx iam.CallContext,
	userID iam.UserID,
) (*iampb.UserInfoData, error) {
	//TODO: access control

	userBaseProfile, err := core.
		GetUserBaseProfile(callCtx, userID)
	if err != nil {
		panic(err)
	}
	baseProfile := &iampb.UserBaseProfileData{
		DisplayName:     userBaseProfile.DisplayName,
		ProfileImageUrl: userBaseProfile.ProfileImageURL,
	}

	var deactivation *iampb.UserAccountDeactivationData
	if userBaseProfile.IsDeleted {
		deactivation = &iampb.UserAccountDeactivationData{
			Deactivated: true,
		}
	}
	accountInfo := &iampb.UserAccountInfoData{
		Verification: &iampb.UserAccountVerificationData{
			Verified: true, //TODO: actual value
		},
		Deactivation: deactivation,
	}

	contactInfo, err := core.
		GetUserContactInformation(callCtx, userID)
	if err != nil {
		panic(err)
	}

	return &iampb.UserInfoData{
		AccountInfo: accountInfo,
		BaseProfile: baseProfile,
		ContactInfo: contactInfo,
	}, nil
}

func (core *Core) GetUserContactInformation(
	callCtx iam.CallContext,
	userID iam.UserID,
) (*iampb.UserContactInfoData, error) {
	//TODO: access control
	userPhoneNumber, err := core.
		GetUserPrimaryPhoneNumber(callCtx, userID)
	if err != nil {
		return nil, errors.Wrap("get user primary phone number", err)
	}
	if userPhoneNumber == nil {
		return nil, nil
	}
	return &iampb.UserContactInfoData{
		PhoneNumber: userPhoneNumber.String(),
	}, nil
}

//TODO(exa): limit profile image url to certain hosts or keep only the filename
func (core *Core) IsUserProfileImageURLAllowed(profileImageURL string) bool {
	return profileImageURL == "" ||
		strings.HasPrefix(profileImageURL, "http://") ||
		strings.HasPrefix(profileImageURL, "https://")
}

func (core *Core) EnsureOrNewUserID(
	callCtx iam.CallContext,
	userID iam.UserID,
) (iam.UserID, error) {
	if callCtx == nil {
		return iam.UserIDZero, errors.ArgMsg("callCtx", "missing")
	}
	if userID.IsValid() {
		if !core.IsUserIDRegistered(userID) {
			return iam.UserIDZero, nil
		}
		return userID, nil
	}

	authCtx := callCtx.Authorization()

	var err error
	tNow := time.Now().UTC()
	userID, err = core.CreateUserAccount(
		authCtx.UserID,
		authCtx.TerminalID(),
		tNow,
	)
	if err != nil {
		return iam.UserIDZero, err
	}

	return userID, nil
}

func (core *Core) CreateUserAccount(
	creationUserID iam.UserID,
	creationTerminalID iam.TerminalID,
	timestamp time.Time,
) (iam.UserID, error) {
	userID, err := core.generateUserID()
	if err != nil {
		panic(err)
	}

	//TODO: if id conflict, generate another id and retry
	_, err = core.db.
		Exec(
			`INSERT INTO users (`+
				`id, creation_time, creation_user_id, creation_terminal_id`+
				`) VALUES (`+
				`$1, $2, $3, $4`+
				`)`,
			userID, timestamp, creationUserID, creationTerminalID)
	if err != nil {
		return iam.UserIDZero, err
	}

	return userID, nil
}

func (core *Core) generateUserID() (iam.UserID, error) {
	var userID iam.UserID
	var err error
	for i := 0; i < 5; i++ {
		userID, err = core.generateUserIDImpl()
		if err == nil && userID.IsValid() {
			return userID, nil
		}
	}
	if err == nil {
		err = errors.Msg("user ID generation failed")
	}
	return iam.UserIDZero, err
}

func (core *Core) generateUserIDImpl() (iam.UserID, error) {
	tNow := time.Now().UTC()
	tbin, err := tNow.MarshalBinary()
	if err != nil {
		panic(err)
	}
	hasher, err := blake2b.New(4, nil)
	if err != nil {
		panic(err)
	}
	hasher.Write(tbin)
	hashPart := hasher.Sum(nil)
	idBytes := make([]byte, 8)
	_, err = rand.Read(idBytes[2:4])
	if err != nil {
		panic(err)
	}
	copy(idBytes[4:], hashPart)
	idUint := binary.BigEndian.Uint64(idBytes) & 0x7fffffffffffffff // ensure sign bit is cleared
	return iam.UserID(idUint), nil
}
