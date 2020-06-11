package iam

import (
	"time"

	"github.com/citadelium/foundation/pkg/errors"
	dataerrs "github.com/citadelium/foundation/pkg/errors/data"
	"github.com/dgrijalva/jwt-go"
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
// token / access token.
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

func (authCtx *Authorization) IsValid() bool {
	return authCtx != nil && authCtx.AuthorizationID.IsValid()
}

func (authCtx *Authorization) IsNotValid() bool {
	return !authCtx.IsValid()
}

func (authCtx *Authorization) Actor() Actor {
	if authCtx == nil {
		return Actor{}
	}
	return Actor{
		UserID:     authCtx.UserID,
		TerminalID: authCtx.AuthorizationID.TerminalID,
	}
}

// IsUserContext is used to determine if this context represents a user.
func (authCtx *Authorization) IsUserContext() bool {
	if authCtx != nil && authCtx.ClientID().IsUserAgent() && authCtx.UserID.IsValid() {
		return true
	}
	return false
}

func (authCtx *Authorization) IsServiceClientContext() bool {
	if authCtx != nil && authCtx.ClientID().IsService() && authCtx.UserID.IsNotValid() {
		return true
	}
	return false
}

// UserIDPtr returns a pointer to a new copy of user ID. The
// returned value is non-nil when the user ID is valid.
func (authCtx *Authorization) UserIDPtr() *UserID {
	if authCtx != nil && authCtx.UserID.IsValid() {
		v := authCtx.UserID
		return &v
	}
	return nil
}

func (authCtx *Authorization) TerminalID() TerminalID {
	if authCtx != nil {
		return authCtx.AuthorizationID.TerminalID
	}
	return 0
}

// TerminalIDPtr returns a pointer to a new copy of terminal ID. The
// returned value is non-nil when the terminal ID is valid.
func (authCtx *Authorization) TerminalIDPtr() *TerminalID {
	if authCtx != nil && authCtx.AuthorizationID.TerminalID.IsValid() {
		v := authCtx.AuthorizationID.TerminalID
		return &v
	}
	return nil
}

func (authCtx *Authorization) ClientID() ClientID {
	if authCtx != nil {
		return authCtx.AuthorizationID.ClientID()
	}
	return 0
}

// RawToken returns the token where this instance of Authorization
// was parsed from.
func (authCtx *Authorization) RawToken() string {
	if authCtx != nil {
		return authCtx.rawToken
	}
	return ""
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
	jwt.StandardClaims

	AuthorizedParty string `json:"azp,omitempty"`
	SubType         string `json:"sub_type,omitempty"`
	TerminalID      string `json:"terminal_id,omitempty"`
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
