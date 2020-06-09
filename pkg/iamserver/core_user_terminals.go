package iamserver

import (
	"github.com/citadelium/pkg/errors"
	"github.com/jmoiron/sqlx"

	"github.com/citadelium/iam/pkg/iam"
)

func (core *Core) DeleteUserTerminalFCMRegistrationToken(
	authCtx *iam.Authorization,
	userID iam.UserID, terminalID iam.TerminalID, token string,
) error {
	_, err := core.db.Exec(
		"UPDATE user_terminal_fcm_registration_tokens "+
			"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2 "+
			"WHERE user_id = $3 AND terminal_id = $4 AND token = $5 AND deletion_time IS NULL",
		authCtx.UserID, authCtx.TerminalID(), userID, terminalID, token)
	return err
}

//TODO: use cache service
func (core *Core) ListUserTerminalIDFirebaseInstanceTokens(
	ownerUserID iam.UserID,
) ([]iam.TerminalIDFirebaseInstanceToken, error) {
	userTermRows, err := core.db.Query(
		"SELECT tid.id, tid.platform_type, tft.token FROM terminals tid "+
			"JOIN user_terminal_fcm_registration_tokens tft "+
			"ON tft.terminal_id=tid.id AND tft.deletion_time IS NULL "+
			"WHERE tid.user_id=$1 AND tid.verification_time IS NOT NULL",
		ownerUserID)
	if err != nil {
		return nil, err
	}
	defer userTermRows.Close()
	var result []iam.TerminalIDFirebaseInstanceToken
	for userTermRows.Next() {
		var item iam.TerminalIDFirebaseInstanceToken
		if err = userTermRows.Scan(&item.TerminalID, &item.PlatformType, &item.Token); err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	if err = userTermRows.Err(); err != nil {
		return nil, err
	}
	return result, nil
}

func (core *Core) SetUserTerminalFCMRegistrationToken(
	callCtx iam.CallContext,
	userID iam.UserID, terminalID iam.TerminalID, token string,
) error {
	if callCtx == nil {
		return errors.ArgMsg("callCtx", "missing")
	}
	authCtx := callCtx.Authorization()

	return doTx(core.db, func(tx *sqlx.Tx) error {
		_, err := tx.Exec(
			"UPDATE user_terminal_fcm_registration_tokens "+
				"SET deletion_time = now(), deletion_user_id = $1, deletion_terminal_id = $2 "+
				"WHERE user_id = $3 AND terminal_id = $4 AND deletion_time IS NULL",
			authCtx.UserID, authCtx.TerminalID(), userID, terminalID)
		if err != nil {
			return err
		}
		if token == "" {
			return nil
		}
		_, err = tx.Exec(
			"INSERT INTO user_terminal_fcm_registration_tokens "+
				"(user_id, terminal_id, creation_user_id, creation_terminal_id, token) "+
				"VALUES ($1, $2, $3, $4, $5)",
			userID, terminalID, authCtx.UserID, authCtx.TerminalID(), token)
		return err
	})
}
