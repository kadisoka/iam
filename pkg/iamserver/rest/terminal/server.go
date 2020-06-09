package terminal

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/citadelium/pkg/api/rest"
	"github.com/citadelium/pkg/errors"
	"github.com/emicklei/go-restful"
	restfulspec "github.com/emicklei/go-restful-openapi"
	"github.com/tomasen/realip"
	"golang.org/x/text/language"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iam/rest/logging"
	"github.com/citadelium/iam/pkg/iamserver"
	"github.com/citadelium/iam/pkg/iamserver/eav10n"
	"github.com/citadelium/iam/pkg/iamserver/pnv10n"
)

var log = logging.NewPkgLogger()

func NewServer(
	basePath string,
	iamServerCore *iamserver.Core,
) *Server {
	return &Server{
		iamserver.RESTServiceServerWith(iamServerCore),
		basePath}
}

type Server struct {
	serverCore *iamserver.RESTServiceServerBase
	basePath   string
}

func (restSrv *Server) RESTRequestContext(req *http.Request) (*iam.RESTRequestContext, error) {
	return restSrv.serverCore.RESTRequestContext(req)
}

func (restSrv *Server) RestfulWebService() *restful.WebService {
	restWS := new(restful.WebService)
	restWS.
		Path(restSrv.basePath).
		Consumes(restful.MIME_JSON).
		Produces(restful.MIME_JSON)

	tags := []string{"iam.v1.terminals"}

	restWS.Route(restWS.
		POST("/register").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSrv.postTerminalsRegister).
		Doc("Terminal registration endpoint").
		Notes("The terminal registration endpoint is used to register "+
			"a terminal. This endpoint will send a verification code "+
			"through the configured external communication channel. "+
			"This code needs to be provided to the terminal secret "+
			"endpoint to obtain the secret of the terminal.\n\n"+
			"A **terminal** is a bound instance of client. It might or "+
			"might not be associated to a user.").
		Param(restWS.
			HeaderParameter(
				"Authorization", "Basic with client credentials.").
			Required(true)).
		Reads(iam.TerminalRegisterPostRequestJSONV1{}).
		Returns(http.StatusOK, "Terminal registered", iam.TerminalRegisterPostResponseJSONV1{}))

	restWS.Route(restWS.
		POST("/secret").
		Deprecate().
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSrv.postTerminalsSecret).
		Doc("Terminal secret endpoint").
		Notes("The terminal secret endpoint is used to obtain the terminal's "+
			"secret by presenting verification code from the terminal "+
			"registration endpoint delivered through the configured "+
			"external communication channel.\n\n"+
			"One verification code can only be used once.\n\n"+
			"A **terminal secret** is required to authenticate the terminal "+
			"to obtain an access token.").
		Reads(iam.TerminalSecretPostRequestJSONV1{}).
		Returns(http.StatusOK, "OK", iam.TerminalSecretPostResponseJSONV1{}).
		Returns(http.StatusGone, "Code is expired", nil))

	restWS.Route(restWS.
		PUT("/fcm_registration_token").
		Metadata(restfulspec.KeyOpenAPITags, tags).
		To(restSrv.putTerminalFCMRegistrationToken).
		Doc("Set terminal's FCM token").
		Notes("Associate the terminal with an FCM registration token. One token should "+
			"be associated to only one terminal.").
		Param(restWS.HeaderParameter("Authorization", "Bearer access token").
			Required(true)).
		Reads(terminalFCMRegistrationTokenPutRequest{}).
		Returns(http.StatusNoContent, "Terminal's FCM token successfully set", nil))

	return restWS
}

//TODO: rate limit
func (restSrv *Server) postTerminalsRegister(
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
			&rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	if reqClient == nil {
		log.WithRequest(req.Request).
			Warn().Msg("No authorized client")
		resp.WriteHeaderAndJson(http.StatusUnauthorized,
			&rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil && err != iam.ErrReqFieldAuthorizationTypeUnsupported {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unable to read authorization")
		resp.WriteHeaderAndJson(http.StatusInternalServerError, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsValid() {
		log.WithContext(reqCtx).
			Warn().Msg("Authorization context must not be valid")
		resp.WriteHeaderAndJson(http.StatusUnauthorized, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	var terminalRegisterReq iam.TerminalRegisterPostRequestJSONV1
	err = req.ReadEntity(&terminalRegisterReq)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unable to read entity from the request body")
		resp.WriteHeaderAndJson(http.StatusBadRequest, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	if terminalRegisterReq.VerificationResourceType == "" {
		if iam.IsValidEmailAddress(terminalRegisterReq.VerificationResourceName) {
			restSrv.handleTerminalRegisterByEmailAddress(
				resp, reqCtx, reqClient, terminalRegisterReq)
			return
		}
		if _, err := iam.PhoneNumberFromString(terminalRegisterReq.VerificationResourceName); err == nil {
			restSrv.handleTerminalRegisterByPhoneNumber(
				resp, reqCtx, reqClient, terminalRegisterReq)
			return
		}

		log.WithContext(reqCtx).
			Warn().Msg("Resource verification type is missing")
		resp.WriteHeaderAndJson(http.StatusBadRequest, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	switch terminalRegisterReq.VerificationResourceType {
	case iam.TerminalVerificationResourceTypeEmailAddress:
		restSrv.handleTerminalRegisterByEmailAddress(
			resp, reqCtx, reqClient, terminalRegisterReq)
		return
	case iam.TerminalVerificationResourceTypePhoneNumber:
		restSrv.handleTerminalRegisterByPhoneNumber(
			resp, reqCtx, reqClient, terminalRegisterReq)
		return

	default:
		log.WithContext(reqCtx).
			Warn().Msgf("Unsupported verification resource type: %v", terminalRegisterReq.VerificationResourceType)
		resp.WriteHeaderAndJson(http.StatusBadRequest, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}
}

func (restSrv *Server) postTerminalsSecret(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unable to load authorization")
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	var linkConfirmReq iam.TerminalSecretPostRequestJSONV1
	err = req.ReadEntity(&linkConfirmReq)
	if err != nil {
		panic(err)
	}

	userTermID, err := iam.TerminalIDFromString(linkConfirmReq.TerminalID)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msgf("Unable to parse terminal ID %q", linkConfirmReq.TerminalID)
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	termSecret, _, err := restSrv.serverCore.
		ConfirmTerminalAuthorization(reqCtx, userTermID, linkConfirmReq.Code)
	if err != nil {
		switch err {
		case iam.ErrTerminalVerificationCodeMismatch:
			log.WithContext(reqCtx).
				Warn().Msgf(
				"Terminal %v verification code mismatch", linkConfirmReq.TerminalID)
			resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
				restful.MIME_JSON)
			return
		case iam.ErrTerminalVerificationCodeExpired:
			log.WithContext(reqCtx).
				Warn().Msgf(
				"Terminal %v verification code expired", linkConfirmReq.TerminalID)
			resp.WriteHeaderAndJson(http.StatusGone, &rest.ErrorResponse{},
				restful.MIME_JSON)
			return
		case iam.ErrTerminalVerificationResourceConflict:
			log.WithContext(reqCtx).
				Warn().Msgf(
				"Terminal %v verification resource conflict", linkConfirmReq.TerminalID)
			resp.WriteHeaderAndJson(http.StatusConflict, &rest.ErrorResponse{},
				restful.MIME_JSON)
			return
		}
		panic(err)
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&iam.TerminalSecretPostResponseJSONV1{
			Secret: termSecret,
		},
		restful.MIME_JSON)

	return
}

func (restSrv *Server) putTerminalFCMRegistrationToken(
	req *restful.Request, resp *restful.Response,
) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("Unable to read authorization")
		resp.WriteHeaderAndJson(http.StatusInternalServerError, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}
	if !reqCtx.IsUserContext() {
		log.WithContext(reqCtx).
			Warn().Msg("Unauthorized request")
		resp.WriteHeaderAndJson(http.StatusUnauthorized, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()

	var fcmRegTokenReq terminalFCMRegistrationTokenPutRequest
	err = req.ReadEntity(&fcmRegTokenReq)
	if err != nil {
		panic(err)
	}

	if fcmRegTokenReq.Token == "" {
		log.WithContext(reqCtx).
			Warn().Msg("Empty token")
		resp.WriteHeaderAndJson(http.StatusBadRequest, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	err = restSrv.serverCore.
		SetUserTerminalFCMRegistrationToken(
			reqCtx, authCtx.UserID, authCtx.TerminalID(),
			fcmRegTokenReq.Token)
	if err != nil {
		panic(err)
	}

	resp.WriteHeader(http.StatusNoContent)
}

// terminal register using phone number
func (restSrv *Server) handleTerminalRegisterByPhoneNumber(
	resp *restful.Response,
	reqCtx *iam.RESTRequestContext,
	authClient *iam.Client,
	terminalRegisterReq iam.TerminalRegisterPostRequestJSONV1,
) {
	// Only for non-confidential user-agents
	if clientID := authClient.ID; !clientID.IsPublic() && !clientID.IsUserAgent() {
		log.WithContext(reqCtx).
			Warn().Msgf("Client %v is not allowed to use this verification resource type", authClient.ID)
		resp.WriteHeaderAndJson(http.StatusForbidden,
			&rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	termLangTags := restSrv.parseRequestAcceptLanguageTags(reqCtx, "")

	phoneNumber, err := iam.PhoneNumberFromString(terminalRegisterReq.VerificationResourceName)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msgf("Unable to parse verification resource name %s of type %s",
			terminalRegisterReq.VerificationResourceName,
			terminalRegisterReq.VerificationResourceType)
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	var verificationMethods []pnv10n.VerificationMethod
	for _, s := range terminalRegisterReq.VerificationMethods {
		m := pnv10n.VerificationMethodFromString(s)
		if m != pnv10n.VerificationMethodUnspecified {
			verificationMethods = append(verificationMethods, m)
		}
	}

	terminalID, _, codeExpiry, err := restSrv.serverCore.
		StartTerminalAuthorizationByPhoneNumber(
			reqCtx, authClient.ID, phoneNumber,
			terminalRegisterReq.DisplayName, reqCtx.HTTPRequest().UserAgent(),
			termLangTags, verificationMethods)
	if err != nil {
		if errors.IsCallError(err) {
			log.WithContext(reqCtx).
				Warn().Err(err).Msgf("StartTerminalAuthorizationByPhoneNumber with %v failed",
				phoneNumber)
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&rest.ErrorResponse{}, restful.MIME_JSON)
			return
		}
		log.WithContext(reqCtx).
			Err(err).Msgf("StartTerminalAuthorizationByPhoneNumber with %v failed",
			phoneNumber)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&iam.TerminalRegisterPostResponseJSONV1{
			TerminalID: terminalID.String(),
			CodeExpiry: codeExpiry,
		},
		restful.MIME_JSON)
	return
}

// terminal registration using email address
func (restSrv *Server) handleTerminalRegisterByEmailAddress(
	resp *restful.Response,
	reqCtx *iam.RESTRequestContext,
	authClient *iam.Client,
	terminalRegisterReq iam.TerminalRegisterPostRequestJSONV1,
) {
	if clientID := authClient.ID; !clientID.IsPublic() && !clientID.IsUserAgent() {
		log.WithContext(reqCtx).
			Warn().Msgf("Client %v is not allowed to use this verification resource type", authClient.ID)
		resp.WriteHeaderAndJson(http.StatusForbidden,
			&rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	termLangTags := restSrv.parseRequestAcceptLanguageTags(reqCtx, "")
	emailAddressStr := terminalRegisterReq.VerificationResourceName
	if !iam.IsValidEmailAddress(emailAddressStr) {
		log.WithContext(reqCtx).Warn().Msgf("Email address %v, is not valid", emailAddressStr)
		resp.WriteHeaderAndJson(http.StatusBadRequest, rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}
	emailAddress, err := iam.EmailAddressFromString(emailAddressStr)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msgf("Unable to parse verification resource name %s of type %s",
			terminalRegisterReq.VerificationResourceName,
			terminalRegisterReq.VerificationResourceType)
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	var verificationMethods []eav10n.VerificationMethod
	for _, s := range terminalRegisterReq.VerificationMethods {
		m := eav10n.VerificationMethodFromString(s)
		if m != eav10n.VerificationMethodUnspecified {
			verificationMethods = append(verificationMethods, m)
		}
	}

	terminalID, _, codeExpiry, err := restSrv.serverCore.
		StartTerminalAuthorizationByEmailAddress(
			reqCtx, authClient.ID, emailAddress,
			terminalRegisterReq.DisplayName, reqCtx.HTTPRequest().UserAgent(),
			termLangTags, verificationMethods)
	if err != nil {
		if errors.IsCallError(err) {
			log.WithContext(reqCtx).
				Warn().Err(err).Msgf("StartTerminalAuthorizationByEmailAddress with %v failed",
				emailAddress)
			resp.WriteHeaderAndJson(http.StatusBadRequest,
				&rest.ErrorResponse{}, restful.MIME_JSON)
			return
		}
		log.WithContext(reqCtx).
			Err(err).Msgf("StartTerminalAuthorizationByEmailAddress with %v failed",
			emailAddress)
		resp.WriteHeader(http.StatusInternalServerError)
		return
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&iam.TerminalRegisterPostResponseJSONV1{
			TerminalID: terminalID.String(),
			CodeExpiry: codeExpiry,
		},
		restful.MIME_JSON)
	return
}

func (restSrv *Server) handleTerminalRegisterByImplicit(
	resp *restful.Response,
	reqCtx *iam.RESTRequestContext,
	authClient *iam.Client,
	terminalRegisterReq iam.TerminalRegisterPostRequestJSONV1,
) {
	// Only if the client is able to secure its credentials.
	if !authClient.ID.IsConfidential() {
		log.WithContext(reqCtx).
			Warn().Msgf("Client %v is not allowed to use this verification resource type", authClient.ID)
		resp.WriteHeaderAndJson(http.StatusForbidden,
			&rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	authCtx := reqCtx.Authorization()
	if authCtx.IsUserContext() {
		//TODO: determine if we should support user context
		log.WithContext(reqCtx).
			Warn().Msgf("Client %v is authenticating by implicit grant with valid user context", authClient.ID)
		resp.WriteHeaderAndJson(http.StatusForbidden,
			&rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	tNow := time.Now().UTC()
	termLangStrings := restSrv.parseRequestAcceptLanguage(reqCtx, "")

	termDisplayName := strings.TrimSpace(terminalRegisterReq.DisplayName)
	var ipAddress string
	var userAgent string
	if httpReq := reqCtx.HTTPRequest(); httpReq != nil {
		ipAddress = realip.FromRequest(reqCtx.HTTPRequest())
		userAgent = httpReq.UserAgent()
	}

	termID, termSecret, err := restSrv.serverCore.
		RegisterTerminal(iamserver.TerminalRegistrationInput{
			ClientID:           authClient.ID,
			UserID:             iam.UserIDZero,
			DisplayName:        termDisplayName,
			AcceptLanguage:     strings.Join(termLangStrings, ","),
			CreationTime:       tNow,
			CreationUserID:     authCtx.UserIDPtr(),
			CreationTerminalID: authCtx.TerminalIDPtr(),
			CreationIPAddress:  ipAddress,
			CreationUserAgent:  userAgent,
			VerificationType:   terminalRegisterReq.VerificationResourceType,
			VerificationID:     0,
		})
	if err != nil {
		panic(err)
	}

	resp.WriteHeaderAndJson(http.StatusOK,
		&iam.TerminalRegisterPostResponseJSONV1{
			TerminalID:     termID.String(),
			TerminalSecret: termSecret,
		},
		restful.MIME_JSON)

	return
}

// Parse accept languages from request
func (restSrv *Server) parseRequestAcceptLanguageTags(
	reqCtx *iam.RESTRequestContext,
	overrideAcceptLanguage string,
) (termLangTags []language.Tag) {
	termLangTags, _, err := language.ParseAcceptLanguage(overrideAcceptLanguage)
	if overrideAcceptLanguage != "" && err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msgf("Unable to parse preferred languages from body %q", overrideAcceptLanguage)
	}
	if len(termLangTags) == 0 || err != nil {
		if httpReq := reqCtx.HTTPRequest(); httpReq != nil {
			var headerLangTags []language.Tag
			headerLangTags, _, err = language.
				ParseAcceptLanguage(httpReq.Header.Get("Accept-Language"))
			if err != nil {
				log.WithContext(reqCtx).
					Warn().Err(err).Msg("Unable to parse preferred languages from HTTP header")
			} else {
				if len(headerLangTags) > 0 {
					termLangTags = headerLangTags
				}
			}
		}
	}

	return termLangTags
}

// Parse accept languages from request
func (restSrv *Server) parseRequestAcceptLanguage(
	reqCtx *iam.RESTRequestContext,
	overrideAcceptLanguage string,
) (termLangStrings []string) {
	termLangTags := restSrv.parseRequestAcceptLanguageTags(reqCtx, overrideAcceptLanguage)
	for _, langTag := range termLangTags {
		termLangStrings = append(termLangStrings, langTag.String())
	}
	return termLangStrings
}

type terminalFCMRegistrationTokenPutRequest struct {
	Token string `json:"token"`
}
