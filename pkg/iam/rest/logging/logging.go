package logging

import (
	"net/http"

	"github.com/citadelium/foundation/pkg/api/rest"
	citadellog "github.com/citadelium/foundation/pkg/logging"
	"github.com/tomasen/realip"

	"github.com/citadelium/iam/pkg/iam"
)

// NewPkgLogger creates a logger for use within a package. This logger
// automatically adds the name of the package where this function was called,
// not when logging.
func NewPkgLogger() Logger {
	return Logger{PkgLogger: citadellog.NewPkgLoggerInternal(citadellog.CallerPkgName())}
}

// Logger wraps other logger to provide additional functionalities.
type Logger struct {
	citadellog.PkgLogger
}

// WithContext creates a new logger which bound to a RequestContext.
//
//TODO: don't populate the entry before the actual logging call.
func (logger Logger) WithContext(
	ctx rest.RequestContext,
) *citadellog.Logger {
	// Implementation notes: don't panic

	if ctx == nil {
		l := logger.With().Str("class", "rest").Logger()
		return &l
	}

	logCtx := logger.With()
	hasAuth := false

	if iamCtx, _ := ctx.(iam.CallContext); iamCtx != nil {
		if authCtx := iamCtx.Authorization(); authCtx.IsValid() {
			logCtx = logCtx.
				Str("user", authCtx.UserID.String()).
				Str("terminal", authCtx.TerminalID().String()).
				Str("auth", authCtx.AuthorizationID.String())
		}
	}

	if req := ctx.HTTPRequest(); req != nil {
		var urlStr string
		if req.URL != nil {
			urlStr = req.URL.String()
		}
		logCtx = logCtx.
			Str("method", req.Method).
			Str("url", urlStr)
		if !hasAuth {
			logCtx = logCtx.
				Str("remote_addr", ctx.RemoteAddress()).
				Str("user_agent", req.UserAgent())
		}
	}

	if reqID := ctx.RequestID(); reqID != nil {
		logCtx = logCtx.
			Str("request_id", reqID.String())
	}

	l := logCtx.Logger()
	return &l
}

// WithRequest creates a log entry with some fields from the request.
func (logger Logger) WithRequest(
	req *http.Request,
) *citadellog.Logger {
	// Implementation notes: don't panic

	if req == nil {
		return &logger.Logger
	}

	var urlStr string
	if req.URL != nil {
		urlStr = req.URL.String()
	}

	remoteAddr := realip.FromRequest(req)
	if remoteAddr == "" {
		remoteAddr = req.RemoteAddr
	}

	l := logger.With().
		Str("method", req.Method).
		Str("url", urlStr).
		Str("remote_addr", remoteAddr).
		Str("user_agent", req.UserAgent()).
		Logger()
	return &l
}
