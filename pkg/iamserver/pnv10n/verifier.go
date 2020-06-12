//
package pnv10n

import (
	"crypto/rand"
	"database/sql"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/kadisoka/foundation/pkg/errors"
	"golang.org/x/text/language"

	"github.com/citadelium/iam/pkg/iam"
)

func NewVerifier(
	appName string,
	db *sqlx.DB,
	config Config,
) *Verifier {
	if appName == "" {
		panic("Invalid config")
	}

	loadTemplates()

	smsDeliveryServices := map[int32]SMSDeliveryService{}
	serviceName := config.SMSDeliveryService
	if serviceName == "" || !strings.Contains(serviceName, ",") {
		if serviceName == "" {
			serviceName = "twilio"
		}
		deliverySvc, err := NewSMSDeliveryService(serviceName, config.Modules[serviceName])
		if err != nil || deliverySvc == nil {
			panic("SMS delivery service not configured")
		}
		smsDeliveryServices[0] = deliverySvc
	} else {
		codeNames := strings.Split(serviceName, ",")
		instantiatedServices := map[string]SMSDeliveryService{}
		for _, codeName := range codeNames {
			parts := strings.Split(codeName, ":")
			svcName := strings.TrimSpace(parts[1])
			svcInst, _ := instantiatedServices[svcName]
			if svcInst == nil {
				deliverySvc, err := NewSMSDeliveryService(svcName, config.Modules[svcName])
				if err != nil || deliverySvc == nil {
					panic("SMS delivery service not configured")
				}
				instantiatedServices[svcName] = deliverySvc
				svcInst = deliverySvc
			}
			ccStr := parts[0]
			if ccStr == "*" {
				smsDeliveryServices[0] = svcInst
			} else {
				countryCode, err := strconv.ParseInt(ccStr, 10, 16)
				if err != nil {
					panic(err)
				}
				if countryCode <= 0 {
					panic("Invalid country code " + ccStr)
				}
				if _, dup := smsDeliveryServices[int32(countryCode)]; dup {
					panic("Duplicate country code " + ccStr)
				}
				smsDeliveryServices[int32(countryCode)] = svcInst
			}
		}
	}
	if _, ok := smsDeliveryServices[0]; !ok {
		panic("Requires at least one SMS delivery service")
	}

	var codeTTLDefault time.Duration
	if config.CodeTTLDefault > 0 {
		codeTTLDefault = config.CodeTTLDefault
	} else {
		codeTTLDefault = 5 * time.Minute //TODO: should be based on the length of the code
	}

	confirmationAttemptsMax := config.ConfirmationAttemptsMax
	if confirmationAttemptsMax == 0 {
		confirmationAttemptsMax = 5
	}

	return &Verifier{
		appName:                 appName,
		db:                      db,
		config:                  config,
		codeTTLDefaultValue:     codeTTLDefault,
		smsDeliveryServices:     smsDeliveryServices,
		confirmationAttemptsMax: confirmationAttemptsMax,
	}
}

type Verifier struct {
	appName                 string
	db                      *sqlx.DB
	codeTTLDefaultValue     time.Duration
	confirmationAttemptsMax int16
	config                  Config
	smsDeliveryServices     map[int32]SMSDeliveryService
}

//TODO(exa): make the operations atomic
func (verifier *Verifier) StartVerification(
	callCtx iam.CallContext,
	phoneNumber iam.PhoneNumber,
	codeTTL time.Duration,
	userPreferredLanguages []language.Tag,
	preferredVerificationMethods []VerificationMethod,
) (id int64, codeExpiry *time.Time, err error) {
	if callCtx == nil {
		return 0, nil, errors.ArgMsg("callCtx", "missing")
	}
	authCtx := callCtx.Authorization()

	tNow := time.Now().UTC()

	var prevAttempts int16
	var prevVerificationID int64
	var prevCodeExpiry time.Time
	err = verifier.db.
		QueryRow(
			"SELECT id, code_expiry, attempts_remaining "+
				"FROM phone_number_verifications "+
				"WHERE country_code = $1 AND national_number = $2 AND confirmation_time IS NULL "+
				"ORDER BY id DESC "+
				"LIMIT 1",
			phoneNumber.CountryCode(),
			phoneNumber.NationalNumber()).
		Scan(&prevVerificationID, &prevCodeExpiry, &prevAttempts)
	if err == nil {
		// Return previous verification code
		if prevAttempts > 0 && prevCodeExpiry.After(tNow.Add(-10*time.Second)) {
			return prevVerificationID, &prevCodeExpiry, nil
		}
	}

	if int64(codeTTL) <= 0 {
		codeTTL = verifier.codeTTLDefaultValue
	}

	code := verifier.generateVerificationCode()
	// Truncate because sub-ms value might be problematic
	// for some parsers. To minute because it's more humane.
	codeExp := tNow.Add(codeTTL).Truncate(time.Minute)
	codeExpiry = &codeExp

	err = verifier.db.
		QueryRow(
			"INSERT INTO phone_number_verifications ("+
				"country_code, national_number, "+
				"creation_time, creation_user_id, creation_terminal_id, "+
				"code, code_expiry, attempts_remaining"+
				") VALUES ($1, $2, $3, $4, $5, $6, $7, $8) "+
				"RETURNING id",
			phoneNumber.CountryCode(),
			phoneNumber.NationalNumber(),
			tNow,
			authCtx.UserID,
			authCtx.TerminalID(),
			code,
			codeExp,
			verifier.confirmationAttemptsMax,
		).Scan(&id)
	if err != nil {
		return 0, nil, err
	}

	noDelivery := len(preferredVerificationMethods) == 1 &&
		preferredVerificationMethods[0] == VerificationMethodNone
	err = verifier.sendTextMessage(
		phoneNumber, code, userPreferredLanguages, noDelivery)
	if err != nil {
		return 0, nil, err
	}

	return
}

func (verifier *Verifier) ConfirmVerification(
	callCtx iam.CallContext,
	verificationID int64, code string,
) error {
	if callCtx == nil {
		return errors.ArgMsg("callCtx", "missing")
	}
	authCtx := callCtx.Authorization()

	var dbData verificationDBModel
	tNow := time.Now().UTC()

	err := verifier.db.QueryRowx(
		`UPDATE phone_number_verifications `+
			`SET attempts_remaining = attempts_remaining - 1 `+
			`WHERE id = $1 `+
			`RETURNING *`,
		verificationID).
		StructScan(&dbData)
	if err != nil {
		return err
	}

	if dbData.AttemptsRemaining < 0 {
		return ErrVerificationCodeExpired
	}
	if dbData.Code != code {
		return ErrVerificationCodeMismatch
	}
	if dbData.CodeExpiry != nil && dbData.CodeExpiry.Before(tNow) {
		// Delete?
		return ErrVerificationCodeExpired
	}

	if dbData.ConfirmationTime != nil {
		return nil
	}

	_, err = verifier.db.Exec(
		"UPDATE phone_number_verifications "+
			"SET confirmation_time = $1, confirmation_user_id = $2, confirmation_terminal_id = $3 "+
			"WHERE id = $4 AND confirmation_time IS NULL",
		tNow, authCtx.UserIDPtr(), authCtx.TerminalIDPtr(), verificationID)
	return err //TODO: determine if it's race-condition
}

func (verifier *Verifier) GetPhoneNumberByVerificationID(
	verificationID int64,
) (*iam.PhoneNumber, error) {
	var countryCode int32
	var nationalNumber int64
	err := verifier.db.QueryRow(
		"SELECT country_code, national_number "+
			"FROM phone_number_verifications "+
			"WHERE id = $1 LIMIT 1",
		verificationID).
		Scan(&countryCode, &nationalNumber)
	if err != nil {
		return nil, err
	}
	result := iam.NewPhoneNumber(countryCode, nationalNumber)
	return &result, nil
}

func (verifier *Verifier) GetVerificationCodeByPhoneNumber(
	phoneNumber iam.PhoneNumber,
) (code string, err error) {
	err = verifier.db.QueryRow(
		"SELECT code "+
			"FROM phone_number_verifications "+
			"WHERE country_code = $1 AND national_number = $2 "+
			"AND confirmation_time IS NULL "+
			"ORDER BY creation_time DESC LIMIT 1",
		phoneNumber.CountryCode(), phoneNumber.NationalNumber()).
		Scan(&code)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return code, nil
}

func (verifier *Verifier) generateVerificationCode() string {
	b := make([]byte, 8)
	_, err := rand.Read(b[5:])
	if err != nil {
		panic(err)
	}
	h := binary.BigEndian.Uint64(b)
	return fmt.Sprintf("%06d", h%1000000)
}

func (verifier *Verifier) sendTextMessage(
	phoneNumber iam.PhoneNumber,
	code string,
	userPreferredLanguages []language.Tag,
	noDelivery bool,
) error {
	var messageTemplate *template.Template
	if len(userPreferredLanguages) != 0 {
		for _, locale := range userPreferredLanguages {
			messageTemplate = localizedMessageTemplates[locale.String()]
			if messageTemplate != nil {
				break
			}
		}
	}
	if messageTemplate == nil {
		messageTemplate = localizedMessageTemplates[messageLocaleDefault.String()]
	}

	var bodyBuilder strings.Builder
	err := messageTemplate.
		Execute(&bodyBuilder, map[string]interface{}{
			"AppName": verifier.appName,
			"Code":    code,
		})
	if err != nil {
		return err
	}

	// https://developers.google.com/identity/sms-retriever/verify
	bodyString := "<#> " + bodyBuilder.String()
	if verifier.config.SMSRetrieverAppHash != "" {
		bodyString += "\n" + verifier.config.SMSRetrieverAppHash
	}

	if !noDelivery {
		//NOTE: special treatment for +1555xxxx numbers (for testing)
		if !(phoneNumber.CountryCode() == 1 && phoneNumber.NationalNumber() > 5550000 && phoneNumber.NationalNumber() <= 5559999) {
			var deliverySvc SMSDeliveryService
			if len(verifier.smsDeliveryServices) > 1 {
				if svc, _ := verifier.smsDeliveryServices[phoneNumber.CountryCode()]; svc != nil {
					deliverySvc = svc
				}
			}
			if deliverySvc == nil {
				deliverySvc = verifier.smsDeliveryServices[0]
			}
			err = deliverySvc.SendTextMessage(phoneNumber.String(), bodyString)
		}
	}

	verifier.notifyChannels(phoneNumber, bodyBuilder.String(), err)

	return err
}

func (verifier *Verifier) notifyChannels(
	phoneNumber iam.PhoneNumber, messageBody string, sendError error,
) {
	textMessage := fmt.Sprintf(
		"Phone number verification for `%s`\n```\n%s```",
		phoneNumber.String(), messageBody)
	if sendError != nil {
		textMessage += "\nWith error: `" + sendError.Error() + "`"
	}
}

var localizedMessageTemplates map[string]*template.Template

//TODO: load these from somewhere (e.g., Firebase remote config)
var localizedMessageTemplateSources = map[string][]string{
	"{{ .AppName }} - verification code: {{ .Code }}":    {"en", "en-US", "en-GB"},
	"{{ .AppName }} - kode verifikasi Anda: {{ .Code }}": {"id", "id-ID"},
}

func loadTemplates() {
	localizedMessageTemplates = make(map[string]*template.Template)
	// Load all message templates. We also ensure that there's no
	// duplicates for the same language.
	for tplstr, locales := range localizedMessageTemplateSources {
		if len(locales) == 0 {
			continue
		}
		tpl := template.Must(template.New("verification-message").Parse(tplstr))
		for _, locale := range locales {
			if locale == "" {
				continue
			}
			langTag := language.MustParse(locale)
			if _, ok := localizedMessageTemplates[langTag.String()]; ok {
				panic("duplicate for locale " + locale + " (" + langTag.String() + ")")
			}
			localizedMessageTemplates[langTag.String()] = tpl
		}
	}
	// Ensure that we have a message template for the default locale.
	if v := localizedMessageTemplates[messageLocaleDefault.String()]; v == nil {
		panic("no template for default locale " + messageLocaleDefault.String())
	}
}
