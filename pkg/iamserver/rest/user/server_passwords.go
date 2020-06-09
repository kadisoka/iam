package user

import (
	"net/http"

	"github.com/citadelium/foundation/pkg/api/rest"
	"github.com/emicklei/go-restful"
)

type userPasswordPutRequest struct {
	Password    string `json:"password"`
	OldPassword string `json:"old_password,omitempty"`
}

func (restSrv *Server) putUserPassword(req *restful.Request, resp *restful.Response) {
	reqCtx, err := restSrv.RESTRequestContext(req.Request)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("Request context")
		resp.WriteHeaderAndJson(http.StatusInternalServerError, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}
	authCtx := reqCtx.Authorization()
	if authCtx.IsNotValid() || !authCtx.IsUserContext() {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Unauthorized")
		resp.WriteHeaderAndJson(http.StatusUnauthorized, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	var reqBody userPasswordPutRequest
	err = req.ReadEntity(&reqBody)
	if err != nil {
		log.WithContext(reqCtx).
			Warn().Err(err).Msg("Request body parsing")
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	matched, err := restSrv.serverCore.
		MatchUserPassword(authCtx.UserID, reqBody.OldPassword)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("Passwords matching")
		resp.WriteHeaderAndJson(http.StatusInternalServerError, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	if !matched {
		log.WithContext(reqCtx).
			Warn().Msg("Passwords mismatch")
		resp.WriteHeaderAndJson(http.StatusBadRequest, &rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	password := reqBody.Password
	if password == "" {
		log.WithContext(reqCtx).
			Warn().Msg("Password empty")
		resp.WriteHeaderAndJson(http.StatusBadRequest,
			&rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	err = restSrv.serverCore.
		SetUserPassword(reqCtx, authCtx.UserID, password)
	if err != nil {
		log.WithContext(reqCtx).
			Err(err).Msg("User password update")
		resp.WriteHeaderAndJson(http.StatusInternalServerError,
			&rest.ErrorResponse{}, restful.MIME_JSON)
		return
	}

	resp.WriteHeader(http.StatusNoContent)
}
