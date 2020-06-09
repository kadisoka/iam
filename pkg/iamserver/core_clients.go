package iamserver

import (
	"github.com/citadelium/iam/pkg/iam"
)

func (core *Core) ClientByID(id iam.ClientID) (*iam.Client, error) {
	if core.clientDataProvider == nil {
		return nil, nil
	}
	return core.clientDataProvider.GetClient(id)
}
