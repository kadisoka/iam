// Package eav10n provides utilities for verifying email addresses.
package eav10n

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	htmltpl "html/template"
	texttpl "text/template"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	awscreds "github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ses"
	"github.com/citadelium/foundation/pkg/app"
	"github.com/citadelium/foundation/pkg/errors"
	"github.com/jmoiron/sqlx"
	"golang.org/x/text/language"

	"github.com/citadelium/iam/pkg/iam"
)

func NewVerifier(
	appInfo app.Info,
	db *sqlx.DB,
	config Config,
) *Verifier {
	emailSenderAddress := appInfo.NotificationEmailSender
	if emailSenderAddress == "" {
		emailSenderAddress = appInfo.Email
	}

	if config.SenderAddress == "" && emailSenderAddress == "" {
		panic("sender address not configured")
	}
	if config.SES == nil || config.SES.Region == "" {
		panic("SES not configured")
	}

	resDir := config.ResourcesDir
	if resDir == "" {
		resDir = ResourcesDirDefault
	}
	loadTemplates(resDir)

	if config.SenderAddress != "" {
		emailSenderAddress = config.SenderAddress
	}

	var creds *awscreds.Credentials
	if config.SES.AccessKeyID != "" {
		creds = awscreds.NewStaticCredentials(
			config.SES.AccessKeyID,
			config.SES.SecretAccessKey,
			"",
		)
	}
	sess, err := session.NewSession(&aws.Config{
		Region:      aws.String(config.SES.Region),
		Credentials: creds,
	})
	if err != nil {
		panic(err)
	}
	svc := ses.New(sess)

	var codeTTLDefault time.Duration
	if config.CodeTTLDefault > 0 {
		codeTTLDefault = config.CodeTTLDefault
	} else {
		codeTTLDefault = 15 * time.Minute //TODO: should be based on the length of the code
	}

	confirmationAttemptsMax := config.ConfirmationAttemptsMax
	if confirmationAttemptsMax == 0 {
		confirmationAttemptsMax = 5
	}

	return &Verifier{
		appInfo:                 appInfo,
		db:                      db,
		senderAddress:           config.SenderAddress,
		sesClient:               svc,
		codeTTLDefault:          codeTTLDefault,
		confirmationAttemptsMax: confirmationAttemptsMax,
	}
}

type Verifier struct {
	appInfo                 app.Info
	db                      *sqlx.DB
	senderAddress           string
	sesClient               *ses.SES
	codeTTLDefault          time.Duration
	confirmationAttemptsMax int16
}

//TODO(exa): make the operations atomic
func (verifier *Verifier) StartVerification(
	callCtx iam.CallContext,
	emailAddress iam.EmailAddress,
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
				"FROM email_address_verifications "+
				"WHERE local_part = $1 AND domain_part = $2 AND confirmation_time IS NULL "+
				"ORDER BY id DESC "+
				"LIMIT 1",
			emailAddress.LocalPart(),
			emailAddress.DomainPart()).
		Scan(&prevVerificationID, &prevCodeExpiry, &prevAttempts)
	if err == nil {
		// Return previous verification code
		if prevAttempts > 0 && prevCodeExpiry.After(tNow.Add(-10*time.Second)) {
			return prevVerificationID, &prevCodeExpiry, nil
		}
	}

	if codeTTL <= 0 {
		codeTTL = verifier.codeTTLDefault
	}

	code := verifier.generateVerificationCode()
	// Truncate because sub-ms value might be problematic
	// for some parsers. To minute because it's more humane.
	codeExp := tNow.Add(codeTTL).Truncate(time.Minute)
	codeExpiry = &codeExp

	err = verifier.db.
		QueryRow(
			`INSERT INTO email_address_verifications `+
				`(local_part, domain_part, code, code_expiry, attempts_remaining, creation_time, creation_user_id, creation_terminal_id) `+
				`VALUES ($1, $2, $3, $4, $5, $6, $7, $8) `+
				`RETURNING id`,
			emailAddress.LocalPart(),
			emailAddress.DomainPart(),
			code,
			codeExp,
			verifier.confirmationAttemptsMax,
			tNow,
			authCtx.UserIDPtr(),
			authCtx.TerminalIDPtr(),
		).Scan(&id)
	if err != nil {
		return 0, nil, err
	}

	noDelivery := len(preferredVerificationMethods) == 1 &&
		preferredVerificationMethods[0] == VerificationMethodNone
	err = verifier.sendVerificationEmail(
		emailAddress, code, userPreferredLanguages, noDelivery)
	if err != nil {
		return 0, nil, err
	}

	return
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
		`UPDATE email_address_verifications `+
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
		return ErrVerificationCodeExpired
	}

	if dbData.ConfirmationTime != nil {
		return nil
	}

	_, err = verifier.db.Exec(
		`UPDATE email_address_verifications `+
			"SET confirmation_time = $1, confirmation_user_id = $2, confirmation_terminal_id = $3 "+
			"WHERE id = $4 AND confirmation_time IS NULL",
		tNow, authCtx.UserIDPtr(), authCtx.TerminalIDPtr(), verificationID)
	return err //TODO: determine if it's race-condition
}

func (verifier *Verifier) sendVerificationEmail(
	emailAddress iam.EmailAddress,
	code string,
	userPreferredLanguages []language.Tag,
	noDelivery bool,
) error {
	var subjectTemplate *texttpl.Template
	var bodyTemplate *htmltpl.Template
	if len(userPreferredLanguages) != 0 {
		for _, locale := range userPreferredLanguages {
			bodyTemplate = localizedAccountActivationBodyHTMLTemplates[locale.String()]
			subjectTemplate = localizedAccountActivationSubjectTemplates[locale.String()]
			if bodyTemplate != nil {
				break
			}
		}
	}
	if bodyTemplate == nil {
		bodyTemplate = localizedAccountActivationBodyHTMLTemplates[messageLocaleDefault.String()]
	}
	if subjectTemplate == nil {
		subjectTemplate = localizedAccountActivationSubjectTemplates[messageLocaleDefault.String()]
	}

	var err error

	buf := new(bytes.Buffer)
	err = subjectTemplate.
		Execute(buf, map[string]interface{}{
			"AppName": verifier.appInfo.Name,
		})
	if err != nil {
		return err
	}
	subject := buf.String()

	buf = new(bytes.Buffer)
	if err = bodyTemplate.Execute(buf, map[string]interface{}{
		"AppInfo": verifier.appInfo,
		"Title":   subject, //TODO: title == subject?
		"Code":    code,
	}); err != nil {
		panic(err)
	}
	htmlBody := buf.String()

	if noDelivery {
		return nil
	}

	// Note that SES supports both text and HTML body. For better
	// support, we might want to utilizes both.
	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{
				aws.String(emailAddress.String()),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Html: &ses.Content{
					Charset: aws.String(messageCharset),
					Data:    aws.String(htmlBody),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String(messageCharset),
				Data:    aws.String(subject),
			},
		},
		Source: aws.String(verifier.senderAddress),
	}

	_, err = verifier.sesClient.SendEmail(input)

	if err != nil {
		if aerr, ok := err.(awserr.Error); ok {
			//TODO: translate errors
			switch aerr.Code() {
			case ses.ErrCodeMessageRejected:
				return errors.Wrap("SendEmail", aerr)
			case ses.ErrCodeMailFromDomainNotVerifiedException:
				return errors.Wrap("SendEmail", aerr)
			case ses.ErrCodeConfigurationSetDoesNotExistException:
				return errors.Wrap("SendEmail", aerr)
			default:
				return errors.Wrap("SendEmail", aerr)
			}
		} else {
			return err
		}
		return err
	}

	return nil
}

func (verifier *Verifier) GetEmailAddressByVerificationID(
	verificationID int64,
) (*iam.EmailAddress, error) {
	var localPart, domainPart string
	err := verifier.db.QueryRow(
		`SELECT local_part, domain_part `+
			`FROM email_address_verifications `+
			`WHERE id = $1 `,
		verificationID).
		Scan(&localPart, &domainPart)
	if err != nil {
		return nil, err
	}
	emailAddress, err := iam.EmailAddressFromString(localPart + "@" + domainPart)
	if err != nil {
		panic(err)
	}
	return &emailAddress, nil
}
