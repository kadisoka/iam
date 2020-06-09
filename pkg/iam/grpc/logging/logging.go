package logging

import (
	"github.com/citadelium/foundation/pkg/api"
	citadellog "github.com/citadelium/foundation/pkg/logging"
	"google.golang.org/grpc"
	grpcPeer "google.golang.org/grpc/peer"

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

// WithContext creates a new logger which bound to a CallContext.
//
//TODO: don't populate the entry before the actual logging call.
func (logger Logger) WithContext(
	ctx api.CallContext,
) *citadellog.Logger {
	// Implementation notes: don't panic

	if ctx == nil {
		l := logger.With().Str("class", "grpc").Logger()
		return &l
	}

	logCtx := logger.With()
	hasAuth := false

	if iamCtx, ok := ctx.(iam.CallContext); ok {
		if authCtx := iamCtx.Authorization(); authCtx.IsValid() {
			logCtx = logCtx.
				Str("user", authCtx.UserID.String()).
				Str("terminal", authCtx.TerminalID().String()).
				Str("auth", authCtx.AuthorizationID.String())
			hasAuth = true
		}
	}
	if !hasAuth {
		if peer, _ := grpcPeer.FromContext(ctx); peer != nil {
			logCtx = logCtx.
				Str("remote_ip", peer.Addr.String())
		}
	}
	if method, ok := grpc.Method(ctx); ok {
		logCtx = logCtx.
			Str("method", method)
	} else {
		logCtx = logCtx.
			Str("method", ctx.MethodName())
	}

	if reqID := ctx.RequestID(); reqID != nil {
		logCtx = logCtx.
			Str("request_id", reqID.String())
	}

	l := logCtx.Logger()
	return &l
}
