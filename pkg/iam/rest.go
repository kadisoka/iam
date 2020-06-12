package iam

import (
	"net/http"

	"github.com/kadisoka/foundation/pkg/api/rest"
)

// RESTServiceClient is the interface specialized for REST.
type RESTServiceClient interface {
	// AuthorizedOutgoingHTTPRequestHeader returns a new instance of http.Header
	// with authorization information set. If baseHeader is proivded, this method
	// will merge it into the returned value.
	AuthorizedOutgoingHTTPRequestHeader(
		baseHeader http.Header,
	) http.Header
}

// RESTServiceClientServer is an interface which contains utilities for
// IAM service clients to handle requests from other clients.
type RESTServiceClientServer interface {
	// RESTRequestContext returns a RESTRequestContext instance for the request.
	// This function will always return an instance even if there's an error.
	RESTRequestContext(*http.Request) (*RESTRequestContext, error)
}

type RESTRequestContext struct {
	CallContext
	Request *http.Request
}

var _ rest.RequestContext = &RESTRequestContext{}

func (reqCtx *RESTRequestContext) HTTPRequest() *http.Request {
	if reqCtx != nil {
		return reqCtx.Request
	}
	return nil
}

func (reqCtx *RESTRequestContext) MethodName() string {
	if reqCtx == nil || reqCtx.Request == nil {
		return ""
	}
	req := reqCtx.Request
	var urlStr string
	if req.URL != nil {
		urlStr = req.URL.String()
	}
	return req.Method + " " + urlStr
}
