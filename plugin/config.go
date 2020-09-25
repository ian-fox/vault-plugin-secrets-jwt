package jwtsecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

// Default values for configuration options.
const (
	DefaultKeyRotationPeriod = "6h0m0s"
	DefaultTokenTTL          = "5m0s"
	DefaultSetIAT            = true
	DefaultSetJTI            = true
	DefaultSetNBF            = true
)

// Config holds all configuration for the backend.
type Config struct {
	// KeyRotationPeriod is how frequently a new key is created.
	KeyRotationPeriod time.Duration

	// TokenTTL defines how long a token is valid for after being signed.
	TokenTTL time.Duration

	// SetIat defines if the backend sets the 'iat' claim or not.
	SetIAT bool

	// SetJTI defines if the backend generates and sets the 'jti' claim or not.
	SetJTI bool

	// SetNBF defines if the backend sets the 'nbf' claim. If true, the claim will be set to the same as the 'iat' claim.
	SetNBF bool

	// Issuer defines the 'iss' claim for the jwt. If blank, it is omitted.
	Issuer string
}

// DefaultConfig creates a new default configuration.
func DefaultConfig(backendUUID string) *Config {
	c := new(Config)
	c.KeyRotationPeriod, _ = time.ParseDuration(DefaultKeyRotationPeriod)
	c.TokenTTL, _ = time.ParseDuration(DefaultTokenTTL)
	c.SetIAT = DefaultSetIAT
	c.SetJTI = DefaultSetJTI
	c.SetNBF = DefaultSetNBF
	return c
}

func readConfig(ctx context.Context, backendUUID string, s logical.Storage) (*Config, error) {
	entry, err := s.Get(ctx, backendUUID)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return DefaultConfig(backendUUID), nil
	}
	c := &Config{}
	if err := entry.DecodeJSON(c); err != nil {
		return nil, err
	}
	return c, nil
}
