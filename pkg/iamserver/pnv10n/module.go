package pnv10n

import (
	"sync"
)

type Module struct {
	ConfigSkeleton        func() interface{} // returns pointer
	NewSMSDeliveryService func(config interface{}) SMSDeliveryService
}

var (
	modules   = map[string]Module{}
	modulesMu sync.RWMutex
)

func ModuleNames() []string {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	var names []string
	for name := range modules {
		names = append(names, name)
	}

	return names
}

func RegisterModule(
	serviceName string,
	module Module,
) {
	modulesMu.Lock()
	defer modulesMu.Unlock()

	if _, dup := modules[serviceName]; dup {
		panic("called twice for service " + serviceName)
	}

	modules[serviceName] = module
}

func NewSMSDeliveryService(
	serviceName string, config interface{},
) (SMSDeliveryService, error) {
	if serviceName == "" {
		return nil, nil
	}

	var module Module
	modulesMu.RLock()
	module, _ = modules[serviceName]
	modulesMu.RUnlock()

	return module.NewSMSDeliveryService(config), nil
}

func ModuleConfigSkeletons() map[string]interface{} {
	modulesMu.RLock()
	defer modulesMu.RUnlock()

	configs := map[string]interface{}{}
	for serviceName, module := range modules {
		if module.ConfigSkeleton != nil {
			configs[serviceName] = module.ConfigSkeleton()
		}
	}

	return configs
}
