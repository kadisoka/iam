package iamserver

import (
	"github.com/kadisoka/iam/pkg/iam/logging"
)

var (
	log    = logging.NewPkgLogger()
	logCtx = log.WithContext
)
