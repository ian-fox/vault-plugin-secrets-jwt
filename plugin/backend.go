// Package jwtsecrets implements the vault-plugin-jwt-secrets backend.
package jwtsecrets

import (
	"context"
	"strings"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type backend struct {
	*framework.Backend
	UUID       string
	clock      clock
	config     *Config
	configLock *sync.RWMutex
	claimsLock *sync.RWMutex
	keys       []*signingKey
	keysLock   *sync.RWMutex
	uuidGen    uuidGenerator
}

// Factory returns a new backend as logical.Backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := makeBackend(conf.BackendUUID)
	if err != nil {
		return nil, err
	}
	if err = b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func makeBackend(BackendUUID string) (*backend, error) {
	var b = &backend{
		UUID: BackendUUID,
	}

	b.keysLock = new(sync.RWMutex)

	b.configLock = new(sync.RWMutex)
	b.claimsLock = new(sync.RWMutex)

	b.clock = realClock{}
	b.uuidGen = realUUIDGenerator{}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeLogical,
		Help:        strings.TrimSpace(backendHelp),
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{"jwks"},
		},
		Paths: []*framework.Path{
			pathConfig(b),
			pathJwks(b),
			pathClaims(b),
			pathSignClaims(b),
			pathSecret(b),
		},
		InitializeFunc: b.initialize,
	}

	return b, nil
}

func (b *backend) initialize(ctx context.Context, r *logical.InitializationRequest) error {
	c, err := readConfig(ctx, b.UUID, r.Storage)
	if err != nil {
		return err
	}
	b.config = c
	return nil
}

const backendHelp = `
The JWT secrets engine signs JWTs.
`
