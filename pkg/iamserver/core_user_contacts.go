package iamserver

import (
	"github.com/citadelium/iam/pkg/iam"
)

func (core *Core) GetUserContactUserIDs(
	callCtx iam.CallContext,
	userID iam.UserID,
) ([]iam.UserID, error) {
	userIDRows, err := core.db.
		Query(
			`SELECT DISTINCT `+
				`ph.user_id `+
				`FROM user_contact_phone_numbers AS cp `+
				`JOIN user_phone_numbers AS ph ON `+
				`  ph.country_code = cp.contact_country_code `+
				`  AND ph.national_number = cp.contact_national_number `+
				`  AND ph.is_primary IS TRUE `+
				`  AND ph.deletion_time IS NULL `+
				`  AND ph.verification_time IS NOT NULL `+
				`JOIN users AS usr ON `+
				`  usr.id = ph.user_id `+
				`  AND usr.deletion_time IS NULL `+
				`WHERE `+
				`  cp.user_id = $1 `+
				`ORDER BY ph.user_id ASC`,
			userID)
	if err != nil {
		return nil, err
	}
	defer userIDRows.Close()

	var userIDs []iam.UserID
	for userIDRows.Next() {
		var userIDStr iam.UserID
		err = userIDRows.Scan(&userIDStr)
		if err != nil {
			panic(err)
		}
		userIDs = append(userIDs, userIDStr)
	}
	if err = userIDRows.Err(); err != nil {
		return nil, err
	}

	return userIDs, nil
}
