package iamserver

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"time"

	"github.com/citadelium/pkg/errors"
	"golang.org/x/text/language"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iamserver/eav10n"
	"github.com/citadelium/iam/pkg/iamserver/pnv10n"
)

var (
	errTerminalVerificationConfirmationReplayed = errors.EntMsg("terminal verification confirmation", "replayed")
)

func (core *Core) AuthenticateTerminal(
	terminalID iam.TerminalID,
	terminalSecret string,
) (authOK bool, ownerUserID iam.UserID, err error) {
	var storedSecret string
	err = core.db.
		QueryRow(
			`SELECT user_id, secret `+
				`FROM terminals `+
				`WHERE id=$1`,
			terminalID).
		Scan(&ownerUserID, &storedSecret)
	if err == sql.ErrNoRows {
		return false, iam.UserIDZero, nil
	}
	if err != nil {
		return false, iam.UserIDZero, err
	}

	return storedSecret == terminalSecret, ownerUserID, nil
}

func (core *Core) StartTerminalAuthorizationByPhoneNumber(
	callCtx iam.CallContext,
	clientID iam.ClientID,
	phoneNumber iam.PhoneNumber,
	displayName string,
	userAgentString string,
	userPreferredLanguages []language.Tag,
	verificationMethods []pnv10n.VerificationMethod,
) (terminalID iam.TerminalID, verificationID int64, codeExpiry *time.Time, err error) {
	authCtx := callCtx.Authorization()

	if !phoneNumber.IsValid() && !core.IsTestPhoneNumber(phoneNumber) {
		return iam.TerminalIDZero, 0, nil, errors.Arg("phoneNumber", nil)
	}

	//TODO: if the number is not already associated to a user, keep using the same
	// user id if we got another request with the same phone number.
	existingOwnerUserID, err := core.
		GetUserIDByPrimaryPhoneNumber(phoneNumber)
	if err != nil {
		panic(err)
	}

	if existingOwnerUserID.IsValid() {
		// As the request is authenticated, check if the phone number
		// is associated to the authenticated user.
		if authCtx.IsUserContext() && existingOwnerUserID != authCtx.UserID {
			return iam.TerminalIDZero, 0, nil, errors.ArgMsg("phoneNumber", "conflict")
		}
	} else {
		newUserID, err := core.
			EnsureOrNewUserID(callCtx, authCtx.UserID)
		if err != nil {
			panic(err)
		}
		_, err = core.
			setUserPrimaryPhoneNumber(
				authCtx.Actor(), newUserID, phoneNumber)
		if err != nil {
			panic(err)
		}
		existingOwnerUserID = newUserID
	}

	tNow := time.Now().UTC()

	userID := existingOwnerUserID
	verificationID, codeExpiry, err = core.pnVerifier.
		StartVerification(callCtx, phoneNumber,
			0, userPreferredLanguages, verificationMethods)
	if err != nil {
		switch err.(type) {
		case pnv10n.InvalidPhoneNumberError:
			return iam.TerminalIDZero, 0, nil, errors.Arg("phoneNumber", err)
		}
		return iam.TerminalIDZero, 0, nil,
			errors.Wrap("pnVerifier.StartVerification", err)
	}

	termLangStrings := make([]string, 0, len(userPreferredLanguages))
	for _, tag := range userPreferredLanguages {
		termLangStrings = append(termLangStrings, tag.String())
	}

	displayName = strings.TrimSpace(displayName)

	terminalID, _, err = core.RegisterTerminal(TerminalRegistrationInput{
		ClientID:           clientID,
		UserID:             userID,
		DisplayName:        displayName,
		AcceptLanguage:     strings.Join(termLangStrings, ","),
		CreationTime:       tNow,
		CreationUserID:     authCtx.UserIDPtr(),
		CreationTerminalID: authCtx.TerminalIDPtr(),
		CreationIPAddress:  "", //TODO: we should be able to get this
		CreationUserAgent:  userAgentString,
		VerificationType:   iam.TerminalVerificationResourceTypePhoneNumber,
		VerificationID:     verificationID,
	})
	if err != nil {
		panic(err)
	}

	return
}

func (core *Core) StartTerminalAuthorizationByEmailAddress(
	callCtx iam.CallContext,
	clientID iam.ClientID,
	emailAddress iam.EmailAddress,
	displayName string,
	userAgentString string,
	userPreferredLanguages []language.Tag,
	verificationMethods []eav10n.VerificationMethod,
) (terminalID iam.TerminalID, verificationID int64, codeExpiry *time.Time, err error) {
	authCtx := callCtx.Authorization()

	if !emailAddress.IsValid() && !core.IsTestEmailAddress(emailAddress) {
		return iam.TerminalIDZero, 0, nil, errors.Arg("emailAddress", nil)
	}

	//TODO: if the address is not already associated to a user, keep using the same
	// user id if we got another request with the same email address.
	existingOwnerUserID, err := core.
		GetUserIDByPrimaryEmailAddress(emailAddress)
	if err != nil {
		panic(err)
	}

	if existingOwnerUserID.IsValid() {
		// As the request is authenticated, check if the phone number
		// is associated to the authenticated user.
		if authCtx.IsUserContext() && existingOwnerUserID != authCtx.UserID {
			return iam.TerminalIDZero, 0, nil, errors.ArgMsg("emailAddress", "conflict")
		}
	} else {
		newUserID, err := core.
			EnsureOrNewUserID(callCtx, authCtx.UserID)
		if err != nil {
			panic(err)
		}
		_, err = core.
			setUserPrimaryEmailAddress(
				authCtx.Actor(), newUserID, emailAddress)
		if err != nil {
			panic(err)
		}
		existingOwnerUserID = newUserID
	}

	tNow := time.Now().UTC()

	userID := existingOwnerUserID
	verificationID, codeExpiry, err = core.eaVerifier.
		StartVerification(callCtx, emailAddress,
			0, userPreferredLanguages, verificationMethods)
	if err != nil {
		switch err.(type) {
		case eav10n.InvalidEmailAddressError:
			return iam.TerminalIDZero, 0, nil, errors.Arg("emailAddress", err)
		}
		return iam.TerminalIDZero, 0, nil,
			errors.Wrap("eaVerifier.StartVerification", err)
	}

	termLangStrings := make([]string, 0, len(userPreferredLanguages))
	for _, tag := range userPreferredLanguages {
		termLangStrings = append(termLangStrings, tag.String())
	}

	displayName = strings.TrimSpace(displayName)

	terminalID, _, err = core.RegisterTerminal(TerminalRegistrationInput{
		ClientID:           clientID,
		UserID:             userID,
		DisplayName:        displayName,
		AcceptLanguage:     strings.Join(termLangStrings, ","),
		CreationTime:       tNow,
		CreationUserID:     authCtx.UserIDPtr(),
		CreationTerminalID: authCtx.TerminalIDPtr(),
		CreationIPAddress:  "", //TODO: we should be able to get this
		CreationUserAgent:  userAgentString,
		VerificationType:   iam.TerminalVerificationResourceTypeEmailAddress,
		VerificationID:     verificationID,
	})
	if err != nil {
		panic(err)
	}

	return
}

//TODO: rate limit
func (core *Core) ConfirmTerminalAuthorization(
	callCtx iam.CallContext,
	terminalID iam.TerminalID,
	verificationCode string,
) (secret string, userID iam.UserID, err error) {
	tNow := time.Now().UTC()

	userTermModel, err := core.getTerminal(terminalID)
	if err != nil {
		panic(err)
	}
	if userTermModel == nil {
		return "", iam.UserIDZero, errors.ArgMsg("terminalID", "reference invalid")
	}
	disallowReplay := false

	if userTermModel.UserID.IsValid() {
		terminalUserID := userTermModel.UserID
		switch userTermModel.VerificationType {
		case iam.TerminalVerificationResourceTypeEmailAddress:
			err = core.eaVerifier.
				ConfirmVerification(
					callCtx,
					userTermModel.VerificationID,
					verificationCode)
			if err != nil {
				switch err {
				case eav10n.ErrVerificationCodeMismatch:
					return "", iam.UserIDZero, iam.ErrTerminalVerificationCodeMismatch
				case eav10n.ErrVerificationCodeExpired:
					return "", iam.UserIDZero, iam.ErrTerminalVerificationCodeExpired
				}
				panic(err)
			}

			emailAddress, err := core.eaVerifier.
				GetEmailAddressByVerificationID(
					userTermModel.VerificationID)
			if err != nil {
				panic(err)
			}

			updated, err := core.
				ensureUserEmailAddressVerifiedFlag(
					terminalUserID,
					*emailAddress,
					&tNow,
					userTermModel.VerificationID)
			if err != nil {
				panic(err)
			}
			if !updated {
				// Let's check if the email address is associated to other user
				existingOwnerUserID, err := core.
					GetUserIDByPrimaryEmailAddress(*emailAddress)
				if err != nil {
					panic(err)
				}
				if existingOwnerUserID.IsValid() && existingOwnerUserID != terminalUserID {
					// The email address has been claimed by another user after
					// the current user requested the link.
					return "", iam.UserIDZero, iam.ErrTerminalVerificationResourceConflict
				}
			}

		case iam.TerminalVerificationResourceTypePhoneNumber:
			err = core.pnVerifier.
				ConfirmVerification(
					callCtx,
					userTermModel.VerificationID,
					verificationCode)
			if err != nil {
				switch err {
				case pnv10n.ErrVerificationCodeMismatch:
					return "", iam.UserIDZero, iam.ErrTerminalVerificationCodeMismatch
				case pnv10n.ErrVerificationCodeExpired:
					return "", iam.UserIDZero, iam.ErrTerminalVerificationCodeExpired
				}
				panic(err)
			}

			phoneNumber, err := core.pnVerifier.
				GetPhoneNumberByVerificationID(
					userTermModel.VerificationID)
			if err != nil {
				panic(err)
			}

			updated, err := core.
				ensureUserPhoneNumberVerifiedFlag(
					terminalUserID,
					*phoneNumber,
					&tNow,
					userTermModel.VerificationID)
			if err != nil {
				panic(err)
			}
			if !updated {
				// Let's check if the phone number is associated to other user
				existingOwnerUserID, err := core.
					GetUserIDByPrimaryPhoneNumber(*phoneNumber)
				if err != nil {
					panic(err)
				}
				if existingOwnerUserID.IsValid() && existingOwnerUserID != terminalUserID {
					// The phone number has been claimed by another user after
					// the current user requested the link.
					return "", iam.UserIDZero, iam.ErrTerminalVerificationResourceConflict
				}
			}

		case iam.TerminalVerificationResourceTypeOAuthAuthorizationCode:
			disallowReplay = true

		default:
			panic("Unsupported")
		}
	}

	termSecret, err := core.
		setUserTerminalVerified(userTermModel.ID, disallowReplay)
	if err != nil {
		if err == errTerminalVerificationConfirmationReplayed {
			return "", iam.UserIDZero, iam.ErrAuthorizationCodeAlreadyClaimed
		}
		panic(err)
	}

	return termSecret, userTermModel.UserID, nil
}

func (core *Core) getTerminal(id iam.TerminalID) (*terminalDBModel, error) {
	var err error
	var ut terminalDBModel
	err = core.db.QueryRowx(
		`SELECT `+
			`id, client_id, user_id, secret, `+
			`creation_time, creation_user_id, creation_terminal_id, creation_ip_address, `+
			`display_name, accept_language, platform_type, `+
			`verification_type, verification_id, verification_time `+
			`FROM terminals `+
			`WHERE id = $1`,
		id).StructScan(&ut)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	return &ut, nil
}

func (core *Core) GetTerminalInfo(
	callCtx iam.CallContext,
	terminalID iam.TerminalID,
) (*iam.TerminalInfo, error) {
	if callCtx == nil {
		return nil, nil
	}
	authCtx := callCtx.Authorization()
	if !authCtx.IsUserContext() {
		return nil, nil
	}

	var ownerUserID iam.UserID
	var displayName string
	var acceptLanguage string
	err := core.db.QueryRow(
		`SELECT user_id, display_name, accept_language `+
			`FROM terminals `+
			`WHERE id = $1`,
		terminalID).
		Scan(&ownerUserID, &displayName, &acceptLanguage)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if ownerUserID != authCtx.UserID {
		return nil, nil
	}

	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil {
		return nil, err
	}
	return &iam.TerminalInfo{
		DisplayName:    displayName,
		AcceptLanguage: tags,
	}, nil
}

// RegisterTerminal registers a terminal. This function returns terminal's
// secret if the verification type is set to 'implicit'.
func (core *Core) RegisterTerminal(input TerminalRegistrationInput) (id iam.TerminalID, secret string, err error) {
	if input.ClientID.IsNotValid() {
		return iam.TerminalIDZero, "", errors.Arg("input.ClientID", nil)
	}
	if input.UserID.IsNotValid() && input.UserID != 0 {
		return iam.TerminalIDZero, "", errors.Arg("input.UserID", nil)
	}

	clientInfo, err := core.ClientByID(input.ClientID)
	if err != nil {
		return iam.TerminalIDZero, "", errors.ArgWrap("input.ClientID", "lookup", err)
	}
	if clientInfo == nil {
		return iam.TerminalIDZero, "", errors.ArgMsg("input.ClientID", "reference invalid")
	}

	//TODO:
	// - check verification type against client type
	// - assert platform type againts client data

	//var verificationID int64
	var termSecret string
	generateSecret := input.VerificationType == iam.TerminalVerificationResourceTypeOAuthClientCredentials
	if generateSecret {
		termSecret = core.generateTerminalSecret()
		input.VerificationTime = &input.CreationTime
	} else {
		termSecret = ""
		input.VerificationTime = nil
	}

	//TODO: if id conflict, generate another id and retry
	termID, err := core.generateTerminalID(input.ClientID)
	_, err = core.db.Exec(
		`INSERT INTO terminals (`+
			`id, client_id, user_id, secret, `+
			`creation_time, creation_user_id, creation_terminal_id, `+
			`creation_ip_address, creation_user_agent, `+
			`display_name, accept_language, platform_type, `+
			`verification_type, verification_id, verification_time `+
			`) VALUES (`+
			`$1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15`+
			`)`,
		termID,
		input.ClientID,
		input.UserID,
		termSecret,
		input.CreationTime,
		input.CreationUserID,
		input.CreationTerminalID,
		input.CreationIPAddress,
		input.CreationUserAgent,
		input.DisplayName,
		input.AcceptLanguage,
		clientInfo.PlatformType,
		input.VerificationType,
		input.VerificationID,
		input.VerificationTime)
	if err != nil {
		return iam.TerminalIDZero, "", err
	}

	if generateSecret {
		return termID, termSecret, nil
	}
	return termID, "", nil
}

func (core *Core) setUserTerminalVerified(
	terminalID iam.TerminalID, disallowReplay bool,
) (secret string, err error) {
	// A secret is used to obtain an access token. if an access token is
	// expired, the terminal could request another access token by
	// providing this secret. the secret is only provided after the
	// authorization has been verified.
	termSecret := core.generateTerminalSecret() //TODO(exa): JWT (or something similar)
	xres, err := core.db.
		Exec(
			"UPDATE terminals SET (secret, verification_time) = ($1, $2) "+
				"WHERE id = $3 AND verification_time IS NULL",
			termSecret, time.Now().UTC(), terminalID)
	if err != nil {
		return "", err
	}
	n, err := xres.RowsAffected()
	if err != nil {
		panic(err)
	}

	if n == 0 {
		if disallowReplay {
			return "", errTerminalVerificationConfirmationReplayed
		}
		err = core.db.
			QueryRow(
				`SELECT secret FROM terminals WHERE id = $1`,
				terminalID).
			Scan(&termSecret)
		if err != nil {
			panic(err)
		}
	}

	return termSecret, nil
}

func (core *Core) generateTerminalID(clientID iam.ClientID) (iam.TerminalID, error) {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	h := uint64(binary.BigEndian.Uint32(b)) & 0x7fffffff // ensure sign bit is cleared
	return iam.TerminalID(uint64(clientID)<<32 | h), nil
}

func (core *Core) generateTerminalSecret() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func (core *Core) getTerminalAcceptLanguages(
	id iam.TerminalID,
) ([]language.Tag, error) {
	var acceptLanguage string
	err := core.db.QueryRow(
		`SELECT accept_language `+
			`FROM terminals `+
			`WHERE id = $1`,
		id).Scan(&acceptLanguage)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	tags, _, err := language.ParseAcceptLanguage(acceptLanguage)
	if err != nil {
		return nil, err
	}
	return tags, nil
}
