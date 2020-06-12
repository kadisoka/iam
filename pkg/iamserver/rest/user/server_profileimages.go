package user

import (
	"net/http"

	"github.com/emicklei/go-restful"
	"github.com/kadisoka/foundation/pkg/api/rest"
	"github.com/kadisoka/foundation/pkg/errors"
)

type userProfileImagePutResponse struct {
	URL string `json:"url"`
}

const multipartFormMaxMemory = 20 * 1024 * 1024

func (restSrv *Server) putUserProfileImage(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).Error().Msgf("Request context: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() && !authCtx.IsUserContext() {
		log.WithContext(reqCtx).Warn().Msgf("Unauthorized: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusUnauthorized)
		return
	}

	if err := req.Request.ParseMultipartForm(multipartFormMaxMemory); err != nil {
		log.WithContext(reqCtx).Error().Msgf("Unable to parse multipart form request: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	uploadedFile, _, err := req.Request.FormFile("body")
	if err != nil {
		log.WithContext(reqCtx).Error().Msgf("Error retrieving the file from request body: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusBadRequest)
		return
	}
	defer uploadedFile.Close()

	imageURL, err := restSrv.serverCore.
		SetUserProfileImageByFile(reqCtx, authCtx.UserID, uploadedFile)
	if err != nil {
		if errors.IsCallError(err) {
			//TODO: translate the error
			log.WithContext(reqCtx).
				Warn().Msgf("Unable to update user profile image: %v", err)
			rest.RespondTo(resp).EmptyError(
				http.StatusBadRequest)
			return
		}
		log.WithContext(reqCtx).
			Error().Msgf("Unable to update user profile image: %v", err)
		rest.RespondTo(resp).EmptyError(
			http.StatusInternalServerError)
		return
	}

	rest.RespondTo(resp).Success(
		&userProfileImagePutResponse{
			URL: imageURL,
		})
}
