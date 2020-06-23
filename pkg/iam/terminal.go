package iam

import (
	"time"

	"github.com/kadisoka/foundation/pkg/errors"
	"golang.org/x/text/language"
)

type TerminalService interface {
	GetTerminalInfo(
		callCtx CallContext,
		terminalID TerminalID,
	) (*TerminalInfo, error)
}

const (
	TerminalVerificationResourceTypePhoneNumber  = "phone-number"
	TerminalVerificationResourceTypeEmailAddress = "email-address"

	TerminalVerificationResourceTypeOAuthAuthorizationCode = "oauth2-authorization-code"
	TerminalVerificationResourceTypeOAuthImplicit          = "oauth2-implicit"
	TerminalVerificationResourceTypeOAuthClientCredentials = "oauth2-client-credentials"
)

var (
	ErrTerminalVerificationCodeMismatch = errors.EntMsg("terminal verification code", "mismatch")
	ErrTerminalVerificationCodeExpired  = errors.EntMsg("terminal verification code", "expired")

	ErrTerminalVerificationResourceConflict = errors.EntMsg("terminal verification resource", "conflict")

	ErrTerminalVerificationResourceNameInvalid = errors.Ent("terminal verification resource name", nil)
)

type TerminalInfo struct {
	DisplayName    string
	AcceptLanguage []language.Tag
}

type TerminalIDFirebaseInstanceToken struct {
	TerminalID   TerminalID
	PlatformType string
	Token        string
}

// JSONV1 models

type TerminalRegisterPostRequestJSONV1 struct {
	DisplayName              string   `json:"display_name"`
	VerificationResourceType string   `json:"verification_resource_type,omitempty"`
	VerificationResourceName string   `json:"verification_resource_name"`
	VerificationMethods      []string `json:"verification_methods"`
}

func (TerminalRegisterPostRequestJSONV1) SwaggerDoc() map[string]string {
	return map[string]string{
		"display_name": "For the user to make it easy to identify. " +
			"The recommended value is the user's device name.",
		"verification_resource_type": "Leave this empty.",
		"verification_resource_name": "A phone number complete with country code or an email address.",
		"verification_methods": "The preferred verification methods. " +
			"The values are resource-type-specific. For phone-number, it defaults to SMS.",
	}
}

// provide user id? indicator for a new user?
type TerminalRegisterPostResponseJSONV1 struct {
	TerminalID     string     `json:"terminal_id"`
	TerminalSecret string     `json:"terminal_secret,omitempty"`
	CodeExpiry     *time.Time `json:"code_expiry,omitempty"`
}

func (TerminalRegisterPostResponseJSONV1) SwaggerDoc() map[string]string {
	return map[string]string{
		"terminal_id": "The ID for the terminal.",
		"terminal_secret": "Contains terminal's secret for certain " +
			"verification resource types",
		"code_expiry": "The time when the verification code will " +
			"be expired.",
	}
}

type TerminalSecretPostRequestJSONV1 struct {
	TerminalID string `json:"terminal_id"`
	Code       string `json:"code"`
}

func (TerminalSecretPostRequestJSONV1) SwaggerDoc() map[string]string {
	return map[string]string{
		"terminal_id": "The ID of the terminal to get the secret for.",
		"code": "The code obtained from the terminal registration endpoint " +
			"delivered through the configured external communication channel.",
	}
}

type TerminalSecretPostResponseJSONV1 struct {
	Secret string `json:"secret"`
}

func (TerminalSecretPostResponseJSONV1) SwaggerDoc() map[string]string {
	return map[string]string{
		"secret": "The secret of the terminal. Provide this secret " +
			"as `password` when requesting an access token. If possible, " +
			"store this secret in a secure storage provided by the OS or " +
			"the platform.",
	}
}
