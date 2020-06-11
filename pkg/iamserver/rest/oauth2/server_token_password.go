//

package oauth2

import (
	"strings"

	"github.com/citadelium/foundation/pkg/api/oauth2"
	"github.com/emicklei/go-restful"

	"github.com/citadelium/iam/pkg/iam"
)

func (restSrv *Server) handleTokenRequestByPasswordGrant(
	req *restful.Request, resp *restful.Response,
) {
	reqClient, err := restSrv.serverCore.
		AuthenticateClientAuthorization(req.Request)
	if err != nil {
		log.WithRequest(req.Request).
			Warn().Err(err).Msg("Client authentication")
		// RFC 6749 § 5.2
		oauth2.RespondTo(resp).ErrInvalidClientBasicAuthorization(
			restSrv.serverCore.RealmName(), "")
		return
	}

	if reqClient != nil && reqClient.ID.IsValid() && (!reqClient.ID.IsUserAgent() || !reqClient.ID.IsConfidential()) {
		log.WithRequest(req.Request).
			Warn().Msgf("Client %v is not authorized to use grant type password", reqClient.ID)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorUnauthorizedClient)
		return
	}

	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil && err != iam.ErrReqFieldAuthorizationTypeUnsupported {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to read authorization: %v", err)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorServerError)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msgf("Authorization context must not be valid")
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorServerError)
		return
	}

	username := req.Request.FormValue("username")
	if username == "" {
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorInvalidGrant)
		return
	}
	password := req.Request.FormValue("password")

	// Username with scheme. The format is '<scheme>:<scheme-specific-identifier>'
	if names := strings.SplitN(username, ":", 2); len(names) == 2 {
		switch names[0] {
		case "terminal":
			restSrv.handleTokenRequestByPasswordGrantWithTerminalCreds(
				reqCtx, resp, reqClient, names[1], password)
			return
		default:
			log.WithRequest(req.Request).
				Warn().Msgf("Unrecognized identifier scheme: %v", names[0])
		}
	}

	log.WithRequest(req.Request).
		Warn().Msgf("Password grant with no scheme.")
	oauth2.RespondTo(resp).ErrorCode(
		oauth2.ErrorInvalidGrant)
}

func (restSrv *Server) handleTokenRequestByPasswordGrantWithTerminalCreds(
	reqCtx *iam.RESTRequestContext,
	resp *restful.Response,
	reqClient *iam.Client,
	terminalIDStr string,
	terminalSecret string,
) {
	terminalID, err := iam.TerminalIDFromString(terminalIDStr)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Msgf("Unable to parse username %q as TerminalID: %v", terminalIDStr, err)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorInvalidGrant)
		return
	}

	authOK, userID, err := restSrv.serverCore.
		AuthenticateTerminal(terminalID, terminalSecret)
	if err != nil {
		log.WithContext(reqCtx).
			Error().Msgf("Terminal %v authentication failed: %v", terminalID, err)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorServerError)
		return
	}
	if !authOK {
		log.WithContext(reqCtx).
			Warn().Msgf("Terminal %v authentication failed", terminalID)
		oauth2.RespondTo(resp).ErrorCode(
			oauth2.ErrorInvalidGrant)
		return
	}

	if userID.IsValid() {
		userAccountState, err := restSrv.serverCore.
			GetUserAccountState(userID)
		if err != nil {
			log.WithContext(reqCtx).
				Warn().Msgf("Terminal %v user account state: %v", terminalID, err)
			oauth2.RespondTo(resp).ErrorCode(
				oauth2.ErrorServerError)
			return
		}
		if userAccountState == nil || !userAccountState.IsAccountActive() {
			var status string
			if userAccountState == nil {
				status = "not exist"
			} else {
				status = "deleted"
			}
			log.WithContext(reqCtx).
				Warn().Msgf("User %v %s", userID, status)
			oauth2.RespondTo(resp).ErrorCode(
				oauth2.ErrorInvalidGrant)
			return
		}
	}

	if reqClient != nil {
		if reqClient.ID != terminalID.ClientID() {
			log.WithContext(reqCtx).
				Error().Msgf("Terminal %v is not associated to client %v", terminalID, reqClient.ID)
			oauth2.RespondTo(resp).ErrorCode(
				oauth2.ErrorServerError)
			return
		}
	}

	accessToken, err := restSrv.serverCore.
		GenerateAccessTokenJWT(reqCtx, terminalID, userID)
	if err != nil {
		panic(err)
	}

	refreshToken, err := restSrv.serverCore.
		GenerateRefreshTokenJWT(terminalID, terminalSecret)
	if err != nil {
		panic(err)
	}

	oauth2.RespondTo(resp).TokenCustom(
		&iam.OAuth2TokenResponse{
			TokenResponse: oauth2.TokenResponse{
				AccessToken:  accessToken,
				TokenType:    oauth2.TokenTypeBearer,
				ExpiresIn:    iam.AccessTokenTTLDefaultInSeconds,
				RefreshToken: refreshToken,
			},
			UserID: userID.String(),
		})
}
