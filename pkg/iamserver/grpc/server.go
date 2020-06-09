package grpc

import (
	"context"
	"fmt"
	"net"

	"github.com/citadelium/pkg/errors"
	"google.golang.org/grpc"

	"github.com/citadelium/iam/pkg/iamserver"
)

type ServerConfig struct {
	ServePort int `env:"SERVE_PORT"`
}

type Server struct {
	config          ServerConfig
	transportServer *grpc.Server
}

// ServerName conforms app.ServiceServer interface.
func (srv *Server) ServerName() string { return "IAM gRPC server" }

// Serve conforms app.Serve interface.
func (srv *Server) Serve() error {
	netListener, err := net.Listen("tcp", fmt.Sprintf(":%d", srv.config.ServePort))
	if err != nil {
		return errors.Wrap("server listen", err)
	}

	err = srv.transportServer.Serve(netListener)
	if err != nil {
		return errors.Wrap("server server", err)
	}

	return nil
}

// Shutdown conforms app.ServiceServer interface.
func (srv *Server) Shutdown(ctx context.Context) error {
	srv.transportServer.GracefulStop()
	log.Info().Msg("gRPC Server done.")
	return nil
}

// IsAcceptingClients conforms app.ServiceServer interface.
func (srv *Server) IsAcceptingClients() bool { return true }

// IsHealthy conforms app.ServiceServer interface.
func (srv *Server) IsHealthy() bool { return true }

func NewServer(
	config ServerConfig,
	iamServerCore *iamserver.Core,
) (*Server, error) {
	srv := &Server{
		config:          config,
		transportServer: grpc.NewServer(),
	}

	NewTerminalAuthorizationServiceServer(iamServerCore, srv.transportServer)

	return srv, nil
}
