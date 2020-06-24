package iam

import (
	"time"

	"github.com/kadisoka/foundation/pkg/errors"
	dataerrs "github.com/kadisoka/foundation/pkg/errors/data"
	"github.com/square/go-jose/v3/jwt"
)

// Used in API call metadata: HTTP header and gRPC call metadata
const (
	AuthorizationMetadataKey    = "Authorization"
	AuthorizationMetadataKeyAlt = "authorization"
)

var (
	ErrReqFieldAuthorizationMalformed = ReqFieldErr("Authorization", dataerrs.ErrMalformed)

	ErrReqFieldAuthorizationTypeUnsupported = ReqFieldErr("Authorization", dataerrs.ErrTypeUnsupported)

	ErrAuthorizationCodeAlreadyClaimed = errors.EntMsg("authorization code", "already claimed")
)

// Authorization is generally used to provide authorization information
// for call or request. An Authorization is usually obtained from authorization
// token / access token provided along the request / call.
type Authorization struct {
	// If this context is an assumed context, this field
	// holds info about the assuming context.
	AssumingAuthorization *Authorization `json:"assuming_authorization,omitempty"`

	// AuthorizationID holds the ID of the token where
	// this context was loaded from. An AuthorizationID is unique across
	// the system and could be used as session identifier.
	AuthorizationID AuthorizationID `json:"jti,omitempty"`

	// If the authorized party represents a user, this
	// filed holds the ID of the authorized user.
	UserID UserID `json:"sub,omitempty"`

	// Scope, expiry time

	rawToken string
}

// newEmptyAuthorization creates a new instance of Authorization without
// any data.
func newEmptyAuthorization() *Authorization {
	return &Authorization{}
}

func (authCtx Authorization) IsValid() bool {
	return authCtx.AuthorizationID.IsValid()
}

func (authCtx Authorization) IsNotValid() bool {
	return !authCtx.IsValid()
}

func (authCtx Authorization) Actor() Actor {
	return Actor{
		UserID:     authCtx.UserID,
		TerminalID: authCtx.AuthorizationID.TerminalID,
	}
}

// IsUserContext is used to determine if this context represents a user.
func (authCtx Authorization) IsUserContext() bool {
	if authCtx.ClientID().IsUserAgent() && authCtx.UserID.IsValid() {
		return true
	}
	return false
}

func (authCtx Authorization) IsServiceClientContext() bool {
	if authCtx.ClientID().IsService() && authCtx.UserID.IsNotValid() {
		return true
	}
	return false
}

// UserIDPtr returns a pointer to a new copy of user ID. The
// returned value is non-nil when the user ID is valid.
func (authCtx Authorization) UserIDPtr() *UserID {
	if authCtx.UserID.IsValid() {
		return &authCtx.UserID
	}
	return nil
}

func (authCtx Authorization) TerminalID() TerminalID {
	return authCtx.AuthorizationID.TerminalID
}

// TerminalIDPtr returns a pointer to a new copy of terminal ID. The
// returned value is non-nil when the terminal ID is valid.
func (authCtx Authorization) TerminalIDPtr() *TerminalID {
	if authCtx.AuthorizationID.TerminalID.IsValid() {
		return &authCtx.AuthorizationID.TerminalID
	}
	return nil
}

func (authCtx Authorization) ClientID() ClientID {
	return authCtx.AuthorizationID.ClientID()
}

// RawToken returns the token where this instance of Authorization
// was parsed from.
func (authCtx Authorization) RawToken() string {
	return authCtx.rawToken
}

const (
	// AccessTokenTTLDefault is the active duration for an access token.
	//
	// We might want to make this configurable.
	AccessTokenTTLDefault = 20 * time.Minute
	// AccessTokenTTLDefaultInSeconds is a shortcut to get AccessTokenTTLDefault in seconds.
	AccessTokenTTLDefaultInSeconds = int64(AccessTokenTTLDefault / time.Second)
)

type AccessTokenClaims struct {
	jwt.Claims

	AuthorizedParty string `json:"azp,omitempty"`
	SubType         string `json:"sub_type,omitempty"`
	TerminalID      string `json:"terminal_id,omitempty"`
}

//TODO: unused. remove this.
func (claims AccessTokenClaims) Valid() error {
	if claims.ID != "" {
		return nil
	}
	return errors.EntMsg("jti", "empty")
}

// RefreshTokenTTLDefault is the active duration for a refresh token.
//
// We might want to make this configurable.
const RefreshTokenTTLDefault = 30 * 24 * time.Hour

type RefreshTokenClaims struct {
	ExpiresAt      int64  `json:"exp,omitempty"`
	NotBefore      int64  `json:"nbf,omitempty"`
	TerminalID     string `json:"terminal_id,omitempty"`
	TerminalSecret string `json:"terminal_secret,omitempty"`
}

// Valid is provided as required for claims. Do not use this method.
func (claims RefreshTokenClaims) Valid() error {
	return nil
}
