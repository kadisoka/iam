package iam

import (
	"context"
	"net/http"
	"strings"

	"github.com/citadelium/foundation/pkg/api"
	"github.com/citadelium/foundation/pkg/errors"
	dataerrs "github.com/citadelium/foundation/pkg/errors/data"
	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	grpcmd "google.golang.org/grpc/metadata"

	"github.com/citadelium/iam/pkg/jose/jws"
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
func (svcClServer *ServiceClientServerCore) GetJWTVerifierKey(keyID string) interface{} {
	return svcClServer.jwtKeyChain.GetJWTVerifierKey(keyID)
}

//HACK: we disable claims validation until all the clients have implemented
// token refresh.
var jwtParser = &jwt.Parser{
	SkipClaimsValidation: true,
}

func (svcClServer *ServiceClientServerCore) AuthorizationFromJWTString(
	jwtStr string,
) (*Authorization, error) {
	emptyAuthCtx := newEmptyAuthorization()
	if jwtStr == "" {
		return emptyAuthCtx, nil
	}

	token, err := jwtParser.ParseWithClaims(
		jwtStr,
		&AccessTokenClaims{},
		func(inToken *jwt.Token) (interface{}, error) {
			algVal := inToken.Header[jws.JOSEHeaderParameterAlgorithm.String()]
			if algStr, ok := algVal.(string); !ok || algStr != "RS256" {
				return emptyAuthCtx, ReqFieldErrMsg("alg", "unsupported")
			}
			kidVal := inToken.Header[jws.JOSEHeaderParameterKeyID.String()]
			kidStr, ok := kidVal.(string)
			if !ok || kidStr == "" {
				return emptyAuthCtx, ReqFieldErrMsg("kid", "empty")
			}
			if key := svcClServer.JWTKeyChain().GetJWTVerifierKey(kidStr); key != nil {
				return key, nil
			}
			return nil, ReqFieldErrMsg("kid", "reference invalid")
		})
	if err != nil {
		//TODO: translate the error
		if errors.IsCallError(err) {
			return emptyAuthCtx, errors.ArgWrap("jwtStr", "validation", err)
		}
		return emptyAuthCtx, errors.Wrap("token validation", err)
	}

	if !token.Valid {
		//TODO: check why it's not valid (expired?)
		return emptyAuthCtx, errors.ArgMsg("jwtStr", "token invalid")
	}

	// Non-safe type-assertion but if it panics, then something has gone totally wrong
	claims := token.Claims.(*AccessTokenClaims)
	if claims.Id == "" {
		return emptyAuthCtx, errors.ArgMsg("jwtStr", "token contains no jti")
	}

	var userID UserID
	if claims.Subject != "" {
		userID, err = UserIDFromString(claims.Subject)
		if err != nil {
			return emptyAuthCtx, errors.ArgMsg("jwtStr", "subject identifier malformed")
		}
		userAccountState, err := svcClServer.userAccountStateService.
			GetUserAccountState(userID)
		if err != nil {
			return emptyAuthCtx, errors.Wrap("account state query", err)
		}
		if userAccountState == nil {
			return emptyAuthCtx, errors.ArgMsg("jwtStr", "subject user ID not registered")
		}
		if !userAccountState.IsAccountActive() {
			return emptyAuthCtx, errors.ArgMsg("jwtStr", "subject account deleted")
		}
	}
	var terminalID TerminalID
	if claims.TerminalID == "" {
		return emptyAuthCtx, errors.ArgMsg("jwtStr", "terminal ID empty")
	}
	terminalID, err = TerminalIDFromString(claims.TerminalID)
	if err != nil {
		return emptyAuthCtx, errors.Arg("jwtStr",
			errors.Ent("terminal_id", dataerrs.Malformed(err)))
	}
	if terminalID.IsNotValid() {
		return emptyAuthCtx, errors.Arg("jwtStr",
			errors.Ent("terminal_id", dataerrs.ErrMalformed))
	}

	//TODO(exa): check if the authorization instance id has been revoked
	authID, err := AuthorizationIDFromString(claims.Id)
	if err != nil {
		return emptyAuthCtx, errors.Arg("jwtStr",
			errors.Ent("id", dataerrs.Malformed(err)))
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
	authCtx, err := svcClServer.authorizationFromGRPCContext(grpcCallCtx)
	if err != nil {
		return newCallContext(grpcCallCtx, authCtx, nil), err
	}
	var requestID *api.RequestID
	md, ok := grpcmd.FromIncomingContext(grpcCallCtx)
	if !ok {
		return newCallContext(grpcCallCtx, authCtx, nil), nil
	}
	reqIDStrs := md.Get("request-id")
	if len(reqIDStrs) == 0 {
		reqIDStrs = md.Get("x-request-id")
	}
	if len(reqIDStrs) > 0 {
		reqIDStr := reqIDStrs[0]
		u, err := uuid.Parse(reqIDStr)
		if err != nil {
			return newCallContext(grpcCallCtx, authCtx, nil),
				ReqFieldErr("Request-ID", dataerrs.Malformed(err))
		}
		if isValidRequestID(u) {
			return newCallContext(grpcCallCtx, authCtx, nil), ReqFieldErr("Request-ID", nil)
		}
		requestID = &u
	}
	return newCallContext(grpcCallCtx, authCtx, requestID), err
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

	// Get from query too?
	var requestID *api.RequestID
	requestIDStr := req.Header.Get("Request-ID")
	if requestIDStr == "" {
		requestIDStr = req.Header.Get("X-Request-ID")
	}
	if requestIDStr != "" {
		u, err := uuid.Parse(requestIDStr)
		if err != nil {
			return newCallContext(ctx, authCtx, nil),
				ReqFieldErr("Request-ID", dataerrs.Malformed(err))
		}
		if isValidRequestID(u) {
			return newCallContext(ctx, authCtx, nil), ReqFieldErr("Request-ID", nil)
		}
		requestID = &u
	}

	return newCallContext(ctx, authCtx, requestID), err
}

func isValidRequestID(u uuid.UUID) bool {
	return u.String() != uuid.Nil.String() &&
		u.Version() == uuid.Version(4) &&
		u.Variant() == uuid.RFC4122
}
