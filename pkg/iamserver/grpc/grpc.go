// Package grpc provides implementation of gRPC API server for IAM service.
//
// Note that this package is highly experimental.
package grpc

import (
	"github.com/kadisoka/iam/pkg/iam/grpc/logging"
)

var (
	log    = logging.NewPkgLogger()
	logCtx = log.WithContext
)
