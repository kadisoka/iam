package user

import (
	"fmt"
	"net/http"
	"strings"

	oidc "github.com/citadelium/foundation/pkg/api/openid/connect"
	"github.com/citadelium/foundation/pkg/api/rest"
	"github.com/emicklei/go-restful"
	restfulspec "github.com/emicklei/go-restful-openapi"

	"github.com/citadelium/iam/pkg/iam"
	"github.com/citadelium/iam/pkg/iam/rest/logging"
	"github.com/citadelium/iam/pkg/iamserver"
)

const (
	phoneNumberListLengthMax = 50
)

var log = logging.NewPkgLogger()

func NewServer(
	basePath string,
	iamServerCore *iamserver.Core,
) *Server {
	return &Server{
		serverCore:    iamserver.RESTServiceServerWith(iamServerCore),
		basePath:      basePath,
		eTagResponder: rest.NewETagResponder(512),
	}
}

type Server struct {
	serverCore    *iamserver.RESTServiceServerBase
	basePath      string
	eTagResponder *rest.ETagResponder
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

	tags := []string{"iam.v1.users"}

	restWS.Route(restWS.
		GET("/{user-id}").
		To(restSrv.getUser).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Retrieve basic profile of current user").
		Produces(restful.MIME_JSON, "application/x-protobuf").
		Param(restWS.HeaderParameter("Authorization", "Bearer access token").
			Required(true)).
		Param(restWS.PathParameter("user-id",
			"Set to a valid user ID or 'me'.").
			Required(true)).
		Returns(http.StatusOK, "OK", iam.UserJSONV1{}))

	restWS.Route(restWS.
		GET("/by_phone_numbers").
		To(restSrv.getUsersByPhoneNumbers).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Retrieve a list of user by their phone numbers").
		Param(restWS.HeaderParameter("Authorization", "Bearer access token").
			Required(true)).
		Param(restWS.QueryParameter("phone_numbers",
			fmt.Sprintf("A comma-separated list of phone numbers (max. %d phone numbers)", phoneNumberListLengthMax)).
			Required(true)).
		Returns(http.StatusOK, "OK", iam.UserPhoneNumberListJSONV1{}))

	restWS.Route(restWS.
		GET("/me/contacts").
		To(restSrv.getUserContacts).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Retrieve a list of user contacts").
		Param(restWS.HeaderParameter("Authorization", "Bearer access token").
			Required(true)).
		Returns(http.StatusOK, "OK", iam.UserContactListsJSONV1{}).
		Returns(http.StatusUnauthorized, "Client authorization check failure", rest.ErrorResponse{}).
		Returns(http.StatusBadRequest, "Request has missing data or contains invalid data", rest.ErrorResponse{}))

	restWS.Route(restWS.
		PUT("/me/password").
		To(restSrv.putUserPassword).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Set password for registered users").
		Param(restWS.HeaderParameter("Authorization", "Bearer access token").
			Required(true)).
		Reads(userPasswordPutRequest{}).
		Returns(http.StatusBadRequest, "Request has missing data or contains invalid data", rest.ErrorResponse{}).
		Returns(http.StatusUnauthorized, "Client authorization check failure", rest.ErrorResponse{}).
		Returns(http.StatusConflict, "Request has duplicate value or contains invalid data", rest.ErrorResponse{}).
		Returns(http.StatusNoContent, "Password set", nil))

	restWS.Route(restWS.
		PUT("/{user-id}/email_address").
		To(restSrv.putUserEmailAddress).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Set a new login email address for the current user").
		Notes("The email address needs to be verified before it's set as user's login "+
			"email address.").
		Param(restWS.HeaderParameter("Authorization", "Bearer access token").
			Required(true)).
		Param(restWS.PathParameter("user-id", "The ID of the user or `me`")).
		Reads(UserEmailAddressPutRequestJSONV1{}).
		Returns(http.StatusAccepted,
			"Email address is accepted by the server and waiting for verification confirmation",
			&UserEmailAddressPutResponse{}).
		Returns(http.StatusNoContent,
			"Provided email address is same as current one.",
			nil))

	restWS.Route(restWS.
		POST("/me/email_address/verification_confirmation").
		To(restSrv.postUserEmailAddressVerificationConfirmation).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Confirm email address verification").
		Reads(UserEmailAddressVerificationConfirmationPostRequest{}).
		Param(restWS.HeaderParameter("Authorization", "Bearer access token").
			Required(false)).
		Returns(http.StatusNoContent,
			"User login email address successfully set", nil))

	restWS.Route(restWS.
		PUT("/me/phone_number").
		To(restSrv.putUserPhoneNumber).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Set a new login phone number for the current user").
		Notes("The phone number needs to be verified before it's set as user's login "+
			"phone number.").
		Param(restWS.
			HeaderParameter(
				"Authorization", "Bearer access token").
			Required(true)).
		Reads(UserPhoneNumberPutRequest{}).
		Returns(
			http.StatusAccepted,
			"Phone number is accepted by the server and waiting for verification confirmation",
			&UserPhoneNumberPutResponse{}).
		Returns(
			http.StatusNoContent,
			"Provided phone number is same as current one.",
			nil))

	restWS.Route(restWS.
		POST("/me/phone_number/verification_confirmation").
		To(restSrv.postUserPhoneNumberVerificationConfirmation).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Confirm phone number verification").
		Reads(UserPhoneNumberVerificationConfirmationPostRequest{}).
		Param(restWS.
			HeaderParameter(
				"Authorization", "Bearer access token").
			Required(false)).
		Returns(
			http.StatusNoContent,
			"User login phone number successfully set", nil))

	restWS.Route(restWS.
		PUT("/me/profile_image").
		Consumes("multipart/form-data").
		To(restSrv.putUserProfileImage).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Update user profile image").
		Param(restWS.
			HeaderParameter(
				"Authorization", "Bearer access token").
			Required(true)).
		Param(restWS.
			FormParameter(
				"body", "File to upload").
			DataType("file").
			Required(true)).
		Returns(http.StatusInternalServerError, "An unexpected condition was encountered in processing the request", nil).
		Returns(http.StatusBadRequest, "The server cannot or will not process the request due to an apparent client error", nil).
		Returns(http.StatusUnauthorized, "Authentication is required and has failed or has not yet been provided", nil).
		Returns(http.StatusNotAcceptable, "The target resource does not have a current representation that would be acceptable.", nil).
		Returns(http.StatusOK, "Profile image updated", userProfileImagePutResponse{}))

	restWS.Route(restWS.
		GET("/me/openidconnect-userinfo").
		To(restSrv.getUserOpenIDConnectUserInfo).
		Metadata(restfulspec.KeyOpenAPITags, tags).
		Doc("Retrieve Claims about the authenticated End-User").
		Notes("The UserInfo Endpoint is an OAuth 2.0 Protected "+
			"Resource that returns Claims about the authenticated "+
			"End-User. To obtain the requested Claims about the End-User, "+
			"the Client makes a request to the UserInfo Endpoint using an "+
			"Access Token obtained through OpenID Connect Authentication. "+
			"These Claims are represented by a JSON object that contains a "+
			"collection of name and value pairs for the Claims.").
		Param(restWS.
			HeaderParameter(
				"Authorization", "Bearer access token").
			Required(true)).
		Returns(http.StatusOK, "OK", oidc.StandardClaims{}))

	return restWS
}

func (restSrv *Server) getUser(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("Request context")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unauthorized")
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	requestedUserIDStr := req.PathParameter("user-id")
	if requestedUserIDStr == "" {
		log.WithContext(reqCtx).
			Warn().Msg("Invalid parameter value path.user-id: empty")
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	var requestedUserID iam.UserID
	if requestedUserIDStr == "me" {
		if !reqCtx.IsUserContext() {
			log.WithContext(reqCtx).
				Warn().Msg("Invalid request: 'me' can only be used with user access token")
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
		requestedUserID = authCtx.UserID
	} else {
		requestedUserID, err = iam.UserIDFromString(requestedUserIDStr)
		if err != nil {
			log.WithContext(reqCtx).
				Warn().Err(err).Msg("Invalid parameter value path.user-id")
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
	}

	if acceptType := req.Request.Header.Get("Accept"); acceptType == "application/x-protobuf" {
		userInfo, err := restSrv.serverCore.
			GetUserInfoV1(reqCtx, requestedUserID)
		if err != nil {
			panic(err)
		}
		restSrv.eTagResponder.RespondGetProtoMessage(req, resp, userInfo)
		return
	}

	userBaseProfile, err := restSrv.serverCore.
		GetUserBaseProfile(reqCtx, requestedUserID)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("User base profile fetch")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	restUserProfile := iam.UserJSONV1FromBaseProfile(userBaseProfile)

	userPhoneNumber, err := restSrv.serverCore.
		GetUserPrimaryPhoneNumber(reqCtx, requestedUserID)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("User phone number fetch")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	if userPhoneNumber != nil {
		restUserProfile.PhoneNumber = userPhoneNumber.String()
	}

	//TODO(exa): should get display email address instead of primary
	// email address for this use case.
	userEmailAddress, err := restSrv.serverCore.
		GetUserPrimaryEmailAddress(reqCtx, requestedUserID)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("User email address fetch")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	if userEmailAddress != nil {
		restUserProfile.EmailAddress = userEmailAddress.RawInput()
	}

	restSrv.eTagResponder.RespondGetJSON(req, resp, restUserProfile)
}

func (restSrv *Server) getUsersByPhoneNumbers(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("Request context")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unauthorized")
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}
	//TODO: check permissions an such

	// use encoding/csv if it became more complex
	phoneNumberStrList := strings.Split(req.QueryParameter("phone_numbers"), ",")
	if len(phoneNumberStrList) == 0 {
		log.WithContext(reqCtx).
			Warn().Msg("Phone number list empty")
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}
	if len(phoneNumberStrList) > phoneNumberListLengthMax {
		log.WithContext(reqCtx).
			Warn().Msgf(
			"Phone number list is too large at %d (max. %d)", len(phoneNumberStrList), phoneNumberListLengthMax)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}

	var unparseablePhoneNumbers []string
	var invalidPhoneNumbers []string
	inputMap := map[string]string{}
	var phoneNumbers []iam.PhoneNumber
	for _, inputStr := range phoneNumberStrList {
		phoneNumber, err := iam.PhoneNumberFromString(inputStr)
		if err != nil {
			unparseablePhoneNumbers = append(unparseablePhoneNumbers, inputStr)
			continue
		}
		if !phoneNumber.IsValid() {
			invalidPhoneNumbers = append(invalidPhoneNumbers, inputStr)
			continue
		}
		normalizedStr := phoneNumber.String()
		if _, exist := inputMap[normalizedStr]; exist {
			continue
		}
		inputMap[normalizedStr] = inputStr
		phoneNumbers = append(phoneNumbers, phoneNumber)
	}

	if len(unparseablePhoneNumbers) > 0 || len(invalidPhoneNumbers) > 0 {
		log.WithContext(reqCtx).
			Warn().
			Strs("unparsable", unparseablePhoneNumbers).
			Strs("invalid", invalidPhoneNumbers).
			Msg("Some phone numbers are ignored")
	}

	userPhoneNumberModelList, err := restSrv.serverCore.
		ListUsersByPhoneNumber(reqCtx, phoneNumbers)
	if err != nil {
		panic(err)
	}

	responseList := []iam.UserPhoneNumberJSONV1{}
	for _, userPhoneNumberModel := range userPhoneNumberModelList {
		phoneNumber := userPhoneNumberModel.PhoneNumber
		responseList = append(responseList, iam.UserPhoneNumberJSONV1{
			UserID:      userPhoneNumberModel.UserID.String(),
			PhoneNumber: inputMap[phoneNumber.String()],
		})
	}

	restSrv.eTagResponder.RespondGetJSON(req, resp,
		iam.UserPhoneNumberListJSONV1{Items: responseList})
}

func (restSrv *Server) getUserContacts(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("Request context")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() || !authCtx.IsUserContext() {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unauthorized")
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	// TODO
	// - Retrieve list of user profile
	// - Return as items of user contacts
	contactUserIDs, err := restSrv.serverCore.GetUserContactUserIDs(
		reqCtx, authCtx.UserID)

	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("User contacts user ID fetch")
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	var userContactLists []iam.UserJSONV1

	if len(contactUserIDs) > 0 {
		for _, contactUserID := range contactUserIDs {
			userBaseProfile, err := restSrv.serverCore.
				GetUserBaseProfile(reqCtx, contactUserID)
			if err != nil {
				panic(err)
			}
			userProfile := iam.UserJSONV1FromBaseProfile(userBaseProfile)

			userPhoneNumber, err := restSrv.serverCore.
				GetUserPrimaryPhoneNumber(reqCtx, contactUserID)

			if err != nil {
				panic(err)
			}

			if userPhoneNumber != nil {
				userProfile.PhoneNumber = userPhoneNumber.String()
			}

			userContactLists = append(userContactLists, *userProfile)
		}
	}

	restSrv.eTagResponder.RespondGetJSON(req, resp,
		&iam.UserContactListsJSONV1{
			Items: userContactLists,
		})
}
