package jws

import (
	"github.com/citadelium/iam/pkg/jose"
)

const (
	JOSEHeaderParameterAlgorithm jose.HeaderParameter = "alg"
	JOSEHeaderParameterKeyID     jose.HeaderParameter = "kid"
)
