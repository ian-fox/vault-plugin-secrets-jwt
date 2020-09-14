package jwtsecrets

import (
	"context"
	"testing"
	"time"

	log "github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/logging"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

const testIssuer = ""

func getTestBackend(t *testing.T) (*backend, *logical.Storage) {
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
		BackendUUID: "test",
	}

	b, err := makeBackend("test")
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.clock = &fakeClock{time.Unix(0, 0)}
	b.uuidGen = &fakeUUIDGenerator{0}
	err = b.initialize(context.Background(), &logical.InitializationRequest{Storage: config.StorageView})
	assert.NoError(t, err, "Should not error")

	return b, &config.StorageView
}

func TestConfigInitialization(t *testing.T) {
	config := &logical.BackendConfig{
		Logger:      logging.NewVaultLogger(log.Trace),
		System:      &logical.StaticSystemView{},
		StorageView: &logical.InmemStorage{},
		BackendUUID: "test",
	}

	b, err := makeBackend("test")
	if err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}
	if err = b.Setup(context.Background(), config); err != nil {
		t.Fatalf("unable to create backend: %v", err)
	}

	b.clock = &fakeClock{time.Unix(0, 0)}
	b.uuidGen = &fakeUUIDGenerator{0}

	backendConfig := Config{
		Issuer: "test",
	}
	entry, err := logical.StorageEntryJSON(b.UUID, backendConfig)
	assert.NoError(t, err, "Should not error")
	err = config.StorageView.Put(context.Background(), entry)
	assert.NoError(t, err, "Should not error")

	err = b.initialize(context.Background(), &logical.InitializationRequest{Storage: config.StorageView})
	assert.NoError(t, err, "Should not error")
	assert.Equal(t, backendConfig.Issuer, b.config.Issuer, "Backend should have been initialized with config in storage")
}
