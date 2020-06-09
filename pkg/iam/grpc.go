package iam

import (
	"context"

	"github.com/citadelium/foundation/pkg/api/grpc"
)

// GRPCServiceClient is the interface specialized for GRPC.
type GRPCServiceClient interface {
	// AuthorizedOutgoingGRPCContext returns a new instance of Context with
	// authorization information set. If baseContext is valid, this method
	// will use it as the parent context, otherwise, this method will create
	// a Background context.
	AuthorizedOutgoingGRPCContext(
		baseContext context.Context,
	) context.Context
}

// GRPCServiceClientServer is an interface which contains utilities for
// IAM service clients to handle requests from other clients.
type GRPCServiceClientServer interface {
	// GRPCCallContext loads authorization context from
	// gRPC call context.
	GRPCCallContext(
		grpcContext context.Context,
	) (*GRPCCallContext, error)
}

type GRPCCallContext struct {
	CallContext
}

var _ grpc.CallContext = &GRPCCallContext{}
