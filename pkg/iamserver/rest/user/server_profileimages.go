package user

import (
	"net/http"

	"github.com/citadelium/pkg/api/rest"
	"github.com/citadelium/pkg/errors"
	"github.com/emicklei/go-restful"
)

type userProfileImagePutResponse struct {
	URL string `json:"url"`
}

const multipartFormMaxMemory = 20 * 1024 * 1024

func (restSrv *Server) putUserProfileImage(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).Error().Msgf("Request context: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() && !authCtx.IsUserContext() {
		log.WithContext(reqCtx).Warn().Msgf("Unauthorized: %v", err)
		resp.WriteHeaderAndJson(http.StatusUnauthorized, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	if err := req.Request.ParseMultipartForm(multipartFormMaxMemory); err != nil {
		log.WithContext(reqCtx).Error().Msgf("Unable to parse multipart form request: %v", err)
		resp.WriteHeaderAndJson(http.StatusInternalServerError, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	uploadedFile, _, err := req.Request.FormFile("body")
	if err != nil {
		log.WithContext(reqCtx).Error().Msgf("Error retrieving the file from request body: %v", err)
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}
	defer uploadedFile.Close()

	imageURL, err := restSrv.serverCore.
		UpdateUserProfileImageByFile(reqCtx, authCtx.UserID, uploadedFile)
	if err != nil {
		if errors.IsCallError(err) {
			//TODO: translate the error
			log.WithContext(reqCtx).
				Warn().Msgf("Unable to update user profile image: %v", err)
			resp.WriteHeaderAndJson(
				http.StatusBadRequest,
				&rest.ErrorResponse{},
				restful.MIME_JSON)
			return
		}
		log.WithContext(reqCtx).
			Error().Msgf("Unable to update user profile image: %v", err)
		resp.WriteHeaderAndJson(
			http.StatusInternalServerError,
			&rest.ErrorResponse{},
			restful.MIME_JSON)
		return
	}

	resp.WriteHeaderAndJson(http.StatusOK, &userProfileImagePutResponse{
		URL: imageURL,
	}, restful.MIME_JSON)
}
