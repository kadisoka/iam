// Package iamserver is the implementation of iam domain logic.
package iamserver

import (
	"github.com/kadisoka/iam/pkg/iam/logging"
)

var (
	log    = logging.NewPkgLogger()
	logCtx = log.WithContext
)
