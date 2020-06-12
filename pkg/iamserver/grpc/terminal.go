package grpc

import (
	"context"

	pbtypes "github.com/gogo/protobuf/types"
	grpcerrs "github.com/kadisoka/foundation/pkg/api/grpc/errors"
	"github.com/kadisoka/foundation/pkg/errors"
	iampb "github.com/rez-go/crux-apis/crux/iam/v1"
	"golang.org/x/text/language"
	"google.golang.org/grpc"
	grpccodes "google.golang.org/grpc/codes"
	grpcmd "google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iamserver"
)

type TerminalAuthorizationServiceServer struct {
	iamServerCore *iamserver.Core
}

func NewTerminalAuthorizationServiceServer(
	iamServerCore *iamserver.Core,
	grpcServer *grpc.Server,
) *TerminalAuthorizationServiceServer {
	authServer := &TerminalAuthorizationServiceServer{
		iamServerCore,
	}
	iampb.RegisterTerminalAuthorizationServiceServer(grpcServer, authServer)
	return authServer
}

//TODO: verification methods
func (authServer *TerminalAuthorizationServiceServer) InitiateUserTerminalAuthorizationByPhoneNumber(
	callCtx context.Context,
	reqProto *iampb.InitiateUserTerminalAuthorizationByPhoneNumberRequest,
) (*iampb.InitiateUserTerminalAuthorizationByPhoneNumberResponse, error) {
	reqCtx, err := authServer.iamServerCore.GRPCCallContext(callCtx)
	if err != nil {
		panic(err) //TODO: translate and return the error
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msgf("Authorization context must not be valid: %#v", reqCtx)
		return nil, grpcstatus.Error(grpccodes.Unauthenticated, "")
	}

	clientID, err := iam.ClientIDFromString(reqProto.ClientCredentials.ClientId)
	if err != nil {
		panic(err)
	}

	termLangTags := authServer.parseRequestAcceptLanguageTags(
		reqProto.TerminalInfo.AcceptLanguage)

	md, _ := grpcmd.FromIncomingContext(callCtx)
	var userAgentString string
	ual := md.Get("user-agent")
	if len(ual) > 0 {
		userAgentString = ual[0]
	}

	phoneNumber, err := iam.PhoneNumberFromString(reqProto.PhoneNumber)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Str("phone_number", reqProto.PhoneNumber).Msg("Phone number format")
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, "")
	}

	terminalID, _, codeExpiry, err := authServer.iamServerCore.
		StartTerminalAuthorizationByPhoneNumber(
			reqCtx, clientID, phoneNumber,
			reqProto.TerminalInfo.DisplayName, userAgentString,
			termLangTags, nil)
	if err != nil {
		switch err.(type) {
		case errors.CallError:
			log.WithContext(reqCtx).
				Warn().Err(err).Msgf("StartTerminalAuthorizationByPhoneNumber with %v failed",
				phoneNumber)
			return nil, grpcstatus.Error(grpccodes.InvalidArgument, "")
		}
		log.WithContext(reqCtx).
			Err(err).Msgf("StartTerminalAuthorizationByPhoneNumber with %v failed",
			phoneNumber)
		return nil, grpcerrs.Error(err)
	}

	var codeExpiryProto *pbtypes.Timestamp
	if codeExpiry != nil {
		codeExpiryProto, err = pbtypes.TimestampProto(*codeExpiry)
		if err != nil {
			panic(err)
		}
	}
	resp := iampb.InitiateUserTerminalAuthorizationByPhoneNumberResponse{
		TerminalId:                 terminalID.String(),
		VerificationCodeExpiryTime: codeExpiryProto,
	}
	return &resp, nil
}

func (authServer *TerminalAuthorizationServiceServer) ConfirmTerminalAuthorization(
	callCtx context.Context, reqProto *iampb.ConfirmTerminalAuthorizationRequest,
) (*iampb.ConfirmTerminalAuthorizationResponse, error) {
	reqCtx, err := authServer.iamServerCore.GRPCCallContext(callCtx)
	if err != nil {
		panic(err) //TODO: translate and return the error
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msgf("Authorization context must not be valid: %#v", authCtx)
		return nil, grpcstatus.Error(grpccodes.Unauthenticated, "")
	}

	termID, err := iam.TerminalIDFromString(reqProto.TerminalId)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msgf("Unable to parse terminal ID %q", reqProto.TerminalId)
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, "")
	}

	termSecret, _, err := authServer.iamServerCore.
		ConfirmTerminalAuthorization(
			reqCtx, termID, reqProto.VerificationCode)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msgf("Terminal authorization confirm failed: %v")
		return nil, grpcerrs.Error(err)
	}

	return &iampb.ConfirmTerminalAuthorizationResponse{
		TerminalSecret: termSecret,
	}, nil
}

func (authServer *TerminalAuthorizationServiceServer) GenerateAccessTokenByTerminalCredentials(
	callCtx context.Context, reqProto *iampb.GenerateAccessTokenByTerminalCredentialsRequest,
) (*iampb.GenerateAccessTokenByTerminalCredentialsResponse, error) {
	reqCtx, err := authServer.iamServerCore.GRPCCallContext(callCtx)
	if err != nil {
		panic(err) //TODO: translate and return the error
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msgf("Authorization context must not be valid: %#v", authCtx)
		return nil, grpcstatus.Error(grpccodes.Unauthenticated, "")
	}

	termID, err := iam.TerminalIDFromString(reqProto.TerminalId)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Str("terminal", reqProto.TerminalId).
			Msg("Terminal ID parsing")
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, "")
	}

	authOK, userID, err := authServer.iamServerCore.
		AuthenticateTerminal(termID, reqProto.TerminalSecret)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Str("terminal", termID.String()).Msg("Terminal authentication")
		return nil, grpcerrs.Error(err)
	}
	if !authOK {
		log.WithContext(reqCtx).
			Warn().Str("terminal", termID.String()).Msg("Terminal authentication")
		return nil, grpcstatus.Error(grpccodes.InvalidArgument, "")
	}

	if userID.IsValid() {
		userAccountState, err := authServer.iamServerCore.
			GetUserAccountState(userID)
		if err != nil {
			log.WithContext(reqCtx).
				Warn().Err(err).Str("terminal", termID.String()).Msg("Terminal user account state")
			return nil, grpcerrs.Error(err)
		}
		if userAccountState == nil || !!userAccountState.IsAccountActive() {
			var status string
			if userAccountState == nil {
				status = "not exist"
			} else {
				status = "deleted"
			}
			log.WithContext(reqCtx).
				Warn().Str("terminal", termID.String()).Str("user", userID.String()).
				Msg("Terminal user account " + status)
			return nil, grpcstatus.Error(grpccodes.InvalidArgument, "")
		}
	}

	tokenString, err := authServer.iamServerCore.
		GenerateAccessTokenJWT(reqCtx, termID, userID)
	if err != nil {
		panic(err)
	}

	return &iampb.GenerateAccessTokenByTerminalCredentialsResponse{
		AccessToken: tokenString,
		AuthorizationData: &iampb.AuthorizationData{
			SubjectUserId: userID.String(),
		},
	}, nil
}

func (authServer *TerminalAuthorizationServiceServer) parseRequestAcceptLanguageTags(
	overrideAcceptLanguage string,
) (termLangTags []language.Tag) {
	termLangTags, _, err := language.ParseAcceptLanguage(overrideAcceptLanguage)
	if err != nil {
		return nil
	}
	return termLangTags
}

func (authServer *TerminalAuthorizationServiceServer) parseRequestAcceptLanguage(
	overrideAcceptLanguage string,
) (termLangStrings []string) {
	termLangTags := authServer.parseRequestAcceptLanguageTags(overrideAcceptLanguage)
	for _, langTag := range termLangTags {
		termLangStrings = append(termLangStrings, langTag.String())
	}
	return termLangStrings
}

func (authServer *TerminalAuthorizationServiceServer) verifyUserTerminalSecret(stored, provided string) bool {
	return stored == provided
}
