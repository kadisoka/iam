package iam

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/kadisoka/foundation/pkg/api"
	"github.com/kadisoka/foundation/pkg/errors"
	dataerrs "github.com/kadisoka/foundation/pkg/errors/data"
	"github.com/square/go-jose/v3/jwt"
	"github.com/tomasen/realip"
	grpcmd "google.golang.org/grpc/metadata"
	grpcpeer "google.golang.org/grpc/peer"
)

// ServiceClientServer is an interface which contains utilities for
// IAM service clients to handle requests from other IAM service clients.
type ServiceClientServer interface {
	// AuthorizationFromJWTString loads authorization context from a JWT
	// string.
	AuthorizationFromJWTString(
		jwtStr string,
	) (*Authorization, error)

	// JWTKeyChain returns instance of key chain used to sign JWT tokens.
	JWTKeyChain() *JWTKeyChain

	GRPCServiceClientServer
	RESTServiceClientServer
}

func NewServiceClientServer(
	jwtKeyChain *JWTKeyChain,
	userAccountStateService UserAccountStateService,
) (ServiceClientServer, error) {
	return &ServiceClientServerCore{
		jwtKeyChain:             jwtKeyChain,
		userAccountStateService: userAccountStateService,
	}, nil
}

type ServiceClientServerCore struct {
	jwtKeyChain             *JWTKeyChain
	userAccountStateService UserAccountStateService
}

var _ ServiceClientServer = &ServiceClientServerCore{}

func (svcClServer *ServiceClientServerCore) JWTKeyChain() *JWTKeyChain {
	return svcClServer.jwtKeyChain
}

// Shortcut
func (svcClServer *ServiceClientServerCore) GetSignedVerifierKey(keyID string) interface{} {
	return svcClServer.jwtKeyChain.GetSignedVerifierKey(keyID)
}

func (svcClServer *ServiceClientServerCore) AuthorizationFromJWTString(
	jwtStr string,
) (*Authorization, error) {
	emptyAuthCtx := newEmptyAuthorization()
	if jwtStr == "" {
		return emptyAuthCtx, nil
	}

	tok, err := jwt.ParseSigned(jwtStr)
	if err != nil {
		return emptyAuthCtx, errors.ArgWrap("", "parsing", err)
	}
	if len(tok.Headers) != 1 {
		return emptyAuthCtx, errors.ArgMsg("", "invalid number of headers")
	}

	keyID := tok.Headers[0].KeyID
	if keyID == "" {
		return emptyAuthCtx, errors.Arg("", errors.EntMsg("kid", "empty"))
	}

	verifierKey := svcClServer.JWTKeyChain().GetSignedVerifierKey(keyID)
	if verifierKey == nil {
		return emptyAuthCtx, errors.Arg("", errors.EntMsg("kid", "reference invalid"))
	}

	var claims AccessTokenClaims
	err = tok.Claims(verifierKey, &claims)
	if err != nil {
		return emptyAuthCtx, errors.ArgWrap("", "verification", err)
	}

	//TODO: check expiry

	if claims.ID == "" {
		return emptyAuthCtx, errors.Arg("", errors.EntMsg("jti", "empty"))
	}
	authID, err := AuthorizationIDFromString(claims.ID)
	if err != nil {
		return emptyAuthCtx, errors.Arg("", errors.Ent("jti", dataerrs.Malformed(err)))
	}
	//TODO(exa): check if the authorization instance id has been revoked

	var userID UserID
	if claims.Subject != "" {
		userID, err = UserIDFromString(claims.Subject)
		if err != nil {
			return emptyAuthCtx, errors.Arg("", errors.EntMsg("sub", "malformed"))
		}
		userAccountState, err := svcClServer.userAccountStateService.
			GetUserAccountState(userID)
		if err != nil {
			return emptyAuthCtx, errors.Wrap("account state query", err)
		}
		if userAccountState == nil {
			return emptyAuthCtx, errors.Arg("", errors.EntMsg("sub", "reference invalid"))
		}
		if !userAccountState.IsAccountActive() {
			return emptyAuthCtx, errors.Arg("", errors.EntMsg("sub", "reference invalid"))
		}
	}

	var terminalID TerminalID
	if claims.TerminalID == "" {
		return emptyAuthCtx, errors.Arg("", errors.EntMsg("terminal_id", "empty"))
	}
	terminalID, err = TerminalIDFromString(claims.TerminalID)
	if err != nil {
		return emptyAuthCtx, errors.Arg("", errors.Ent("terminal_id", dataerrs.Malformed(err)))
	}
	if terminalID.IsNotValid() {
		return emptyAuthCtx, errors.Arg("", errors.Ent("terminal_id", dataerrs.ErrMalformed))
	}

	return &Authorization{
		AuthorizationID: authID,
		UserID:          userID,
		rawToken:        jwtStr,
	}, nil
}

func (svcClServer *ServiceClientServerCore) GRPCCallContext(
	grpcCallCtx context.Context,
) (*GRPCCallContext, error) {
	callCtx, err := svcClServer.callContextFromGRPCContext(grpcCallCtx)
	if callCtx == nil {
		callCtx = NewEmptyCallContext(grpcCallCtx)
	}
	return &GRPCCallContext{callCtx}, err
}

func (svcClServer *ServiceClientServerCore) callContextFromGRPCContext(
	grpcCallCtx context.Context,
) (CallContext, error) {
	var remoteAddr string
	if peer, _ := grpcpeer.FromContext(grpcCallCtx); peer != nil {
		remoteAddr = peer.Addr.String() //TODO: attempt to resolve if it's proxied
	}

	authCtx, err := svcClServer.authorizationFromGRPCContext(grpcCallCtx)
	if err != nil {
		return newCallContext(grpcCallCtx, authCtx, remoteAddr, nil), err
	}
	var requestID *api.RequestID
	md, ok := grpcmd.FromIncomingContext(grpcCallCtx)
	if !ok {
		return newCallContext(grpcCallCtx, authCtx, remoteAddr, nil), nil
	}
	reqIDStrs := md.Get("request-id")
	if len(reqIDStrs) == 0 {
		reqIDStrs = md.Get("x-request-id")
	}
	if len(reqIDStrs) > 0 {
		reqIDStr := reqIDStrs[0]
		u, err := uuid.Parse(reqIDStr)
		if err != nil {
			return newCallContext(grpcCallCtx, authCtx, remoteAddr, nil),
				ReqFieldErr("Request-ID", dataerrs.Malformed(err))
		}
		if isValidRequestID(u) {
			return newCallContext(grpcCallCtx, authCtx, remoteAddr, nil), ReqFieldErr("Request-ID", nil)
		}
		requestID = &u
	}
	return newCallContext(grpcCallCtx, authCtx, remoteAddr, requestID), err
}

func (svcClServer *ServiceClientServerCore) authorizationFromGRPCContext(
	grpcContext context.Context,
) (*Authorization, error) {
	emptyAuthCtx := newEmptyAuthorization()
	md, ok := grpcmd.FromIncomingContext(grpcContext)
	if !ok {
		return emptyAuthCtx, nil
	}
	authorizations := md.Get(AuthorizationMetadataKey)
	if len(authorizations) == 0 {
		return emptyAuthCtx, nil
	}
	if authorizations[0] == "" {
		return emptyAuthCtx, ReqFieldErr("Authorization", dataerrs.ErrEmpty)
	}
	token := authorizations[0]
	parts := strings.SplitN(token, " ", 2)
	if len(parts) == 2 {
		if strings.ToLower(parts[0]) != "bearer" {
			return emptyAuthCtx, ErrReqFieldAuthorizationTypeUnsupported
		}
		token = parts[1]
	}
	return svcClServer.AuthorizationFromJWTString(token)
}

func (svcClServer *ServiceClientServerCore) RESTRequestContext(
	req *http.Request,
) (*RESTRequestContext, error) {
	callCtx, err := svcClServer.callContextFromHTTPRequest(req)
	if callCtx == nil {
		callCtx = NewEmptyCallContext(req.Context())
	}
	return &RESTRequestContext{callCtx, req}, err
}

func (svcClServer *ServiceClientServerCore) callContextFromHTTPRequest(
	req *http.Request,
) (CallContext, error) {
	if _, ok := req.Header["Authorization"]; !ok {
		return nil, nil
	}

	ctx := req.Context()

	authorization := strings.TrimSpace(req.Header.Get("Authorization"))
	//NOTE: for testing using Swagger UI, the header might be set
	// even though after it has been cleared.
	if authorization == "" {
		return nil, nil
	}

	authParts := strings.SplitN(authorization, " ", 2)
	if len(authParts) != 2 {
		return nil, ErrReqFieldAuthorizationMalformed
	}
	if authParts[0] != "Bearer" {
		return nil, ErrReqFieldAuthorizationTypeUnsupported
	}

	jwtStr := strings.TrimSpace(authParts[1])
	authCtx, err := svcClServer.AuthorizationFromJWTString(jwtStr)
	remoteAddr := realip.FromRequest(req)
	if remoteAddr == "" {
		remoteAddr = req.RemoteAddr
	}

	// Get from query too?
	var requestID *api.RequestID
	requestIDStr := req.Header.Get("Request-ID")
	if requestIDStr == "" {
		requestIDStr = req.Header.Get("X-Request-ID")
	}
	if requestIDStr != "" {
		u, err := uuid.Parse(requestIDStr)
		if err != nil {
			return newCallContext(ctx, authCtx, remoteAddr, nil),
				ReqFieldErr("Request-ID", dataerrs.Malformed(err))
		}
		if isValidRequestID(u) {
			return newCallContext(ctx, authCtx, remoteAddr, nil), ReqFieldErr("Request-ID", nil)
		}
		requestID = &u
	}

	return newCallContext(ctx, authCtx, remoteAddr, requestID), err
}

func isValidRequestID(u uuid.UUID) bool {
	return u.String() != uuid.Nil.String() &&
		u.Version() == uuid.Version(4) &&
		u.Variant() == uuid.RFC4122
}
