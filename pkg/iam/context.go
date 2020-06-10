package iam

import (
	"context"

	"github.com/citadelium/foundation/pkg/api"
	accesserrs "github.com/citadelium/foundation/pkg/errors/access"
)

var (
	ErrAuthorizationRequired = accesserrs.Msg("authorization context required")

	ErrUserContextRequired          = accesserrs.Msg("user context required")
	ErrServiceClientContextRequired = accesserrs.Msg("service client context required")

	ErrContextUserNotAllowedToPerformActionOnResource = accesserrs.Msg("context user is not allowed perform action on the target resource")
	ErrContextUserNotAllowedToAccessToOthersResource  = accesserrs.Msg("context user is not allowed to access to other's resource")
)

func NewEmptyCallContext(ctx context.Context) CallContext {
	return &callContext{
		Context:       ctx,
		authorization: newEmptyAuthorization(),
	}
}

// CallContext provides call-scoped information.
type CallContext interface {
	api.CallContext
	Authorization() Authorization
	IsUserContext() bool
}

func newCallContext(
	ctx context.Context,
	authCtx *Authorization,
	remoteAddress string,
	requestID *api.RequestID,
) CallContext {
	if authCtx == nil {
		panic("authCtx must not be nil")
	}
	return &callContext{ctx, authCtx, remoteAddress, requestID}
}

var _ CallContext = &callContext{}

type callContext struct {
	context.Context
	authorization *Authorization
	remoteAddress string
	requestID     *api.RequestID
}

func (ctx callContext) Authorization() Authorization {
	if ctx.authorization == nil {
		authCtx := newEmptyAuthorization()
		return *authCtx
	}
	return *ctx.authorization
}

func (ctx *callContext) IsUserContext() bool {
	return ctx != nil && ctx.authorization != nil &&
		ctx.authorization.IsUserContext()
}

func (ctx *callContext) MethodName() string { return "" }

func (ctx *callContext) RequestID() *api.RequestID { return ctx.requestID }

func (ctx *callContext) RemoteAddress() string { return ctx.remoteAddress }
