//

package oauth2

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/citadelium/pkg/api/oauth2"
	"github.com/emicklei/go-restful"
	"github.com/tomasen/realip"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iamserver"
)

func (restSrv *Server) handleTokenRequestByClientCredentials(
	req *restful.Request, resp *restful.Response,
) {
	reqClient, err := restSrv.serverCore.
		AuthenticateClientAuthorization(req.Request)
	if err != nil {
		log.WithRequest(req.Request).
			Warn().Err(err).Msg("Client authentication")
		// RFC 6749 § 5.2
		realmName := restSrv.serverCore.RealmName()
		if realmName == "" {
			realmName = "Restricted"
		}
		resp.Header().Set("WWW-Authenticate", fmt.Sprintf("Basic realm=%q", realmName))
		resp.WriteHeaderAndJson(http.StatusUnauthorized,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
			restful.MIME_JSON)
		return
	}

	if reqClient == nil {
		log.WithRequest(req.Request).
			Warn().Msg("No authorized client")
		resp.WriteHeaderAndJson(http.StatusUnauthorized,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
			restful.MIME_JSON)
		return
	}

	// To use this grant type, the client must be able to secure its credentials.
	if !reqClient.ID.IsConfidential() {
		log.WithRequest(req.Request).
			Warn().Msgf("Client %v is not allowed to use grant type 'client_credentials'", reqClient.ID)
		resp.WriteHeaderAndJson(http.StatusForbidden,
			&oauth2.ErrorResponse{Error: oauth2.ErrorInvalidClient},
			restful.MIME_JSON)
		return
	}

	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil && err != iam.ErrReqFieldAuthorizationTypeUnsupported {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unable to read authorization")
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msg("Authorization context must not be valid")
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	tNow := time.Now().UTC()
	preferredLanguages := restSrv.parseRequestAcceptLanguage(req, reqCtx, "")
	termDisplayName := ""

	termID, termSecret, err := restSrv.serverCore.
		RegisterTerminal(iamserver.TerminalRegistrationInput{
			ClientID:           reqClient.ID,
			UserID:             authCtx.UserID,
			DisplayName:        termDisplayName,
			AcceptLanguage:     strings.Join(preferredLanguages, ","),
			CreationTime:       tNow,
			CreationUserID:     authCtx.UserIDPtr(),
			CreationTerminalID: authCtx.TerminalIDPtr(),
			CreationIPAddress:  realip.FromRequest(req.Request),
			CreationUserAgent:  strings.TrimSpace(req.Request.UserAgent()),
			VerificationType:   iam.TerminalVerificationResourceTypeOAuthClientCredentials,
			VerificationID:     0,
		})
	if err != nil {
		log.WithContext(reqCtx).
			Error().Msgf("RegisterTerminal: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	accessToken, err := restSrv.serverCore.
		GenerateAccessTokenJWT(reqCtx, termID, authCtx.UserID)
	if err != nil {
		log.WithContext(reqCtx).
			Error().Msgf("GenerateAccessTokenJWT: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	//TODO: properly get the secret
	refreshToken, err := restSrv.serverCore.
		GenerateRefreshTokenJWT(termID, termSecret)
	if err != nil {
		log.WithContext(reqCtx).
			Error().Msgf("GenerateRefreshTokenJWT: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&oauth2.ErrorResponse{Error: oauth2.ErrorServerError},
			restful.MIME_JSON)
		return
	}

	resp.WriteHeaderAndJson(
		http.StatusOK,
		&iam.OAuth2TokenResponse{
			TokenResponse: oauth2.TokenResponse{
				AccessToken:  accessToken,
				TokenType:    oauth2.TokenTypeBearer,
				ExpiresIn:    iam.AccessTokenTTLInSeconds,
				RefreshToken: refreshToken,
			},
			UserID:         authCtx.UserID.String(),
			TerminalID:     termID.String(),
			TerminalSecret: termSecret,
		},
		restful.MIME_JSON)
}
