package jwtsecrets

import (
	"context"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	keyRotationDuration = "key_ttl"
	keyTokenTTL         = "jwt_ttl"
	keySetIAT           = "set_iat"
	keySetJTI           = "set_jti"
	keySetNBF           = "set_nbf"
	keyIssuer           = "issuer"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			keyRotationDuration: {
				Type:        framework.TypeString,
				Description: `Duration before a key stops being used to sign new tokens.`,
			},
			keyTokenTTL: {
				Type:        framework.TypeString,
				Description: `Duration a token is valid for.`,
			},
			keySetIAT: {
				Type:        framework.TypeBool,
				Description: `Whether or not the backend should generate and set the 'iat' claim.`,
			},
			keySetJTI: {
				Type:        framework.TypeBool,
				Description: `Whether or not the backend should generate and set the 'jti' claim.`,
			},
			keySetNBF: {
				Type:        framework.TypeBool,
				Description: `Whether or not the backend should generate and set the 'nbf' claim.`,
			},
			keyIssuer: {
				Type:        framework.TypeString,
				Description: `Value to set as the 'iss' claim. Claim is omitted if empty.`,
			},
		},

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
		},

		HelpSynopsis:    pathConfigHelpSyn,
		HelpDescription: pathConfigHelpDesc,
	}
}

func (b *backend) pathConfigWrite(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	if newRotationPeriod, ok := d.GetOk(keyRotationDuration); ok {
		duration, err := time.ParseDuration(newRotationPeriod.(string))
		if err != nil {
			return nil, err
		}
		b.config.KeyRotationPeriod = duration
	}

	if newTTL, ok := d.GetOk(keyTokenTTL); ok {
		duration, err := time.ParseDuration(newTTL.(string))
		if err != nil {
			return nil, err
		}
		b.config.TokenTTL = duration
	}

	if newSetIat, ok := d.GetOk(keySetIAT); ok {
		b.config.SetIAT = newSetIat.(bool)
	}

	if newSetJTI, ok := d.GetOk(keySetJTI); ok {
		b.config.SetJTI = newSetJTI.(bool)
	}

	if newSetNBF, ok := d.GetOk(keySetNBF); ok {
		b.config.SetNBF = newSetNBF.(bool)
	}

	if newIssuer, ok := d.GetOk(keyIssuer); ok {
		b.config.Issuer = newIssuer.(string)
	}

	entry, err := logical.StorageEntryJSON(b.UUID, b.config)
	if err != nil {
		return nil, err
	}
	err = r.Storage.Put(ctx, entry)
	if err != nil {
		return logical.ErrorResponse("Failed to save claim"), err
	}

	return nonLockingRead(b)
}

func (b *backend) pathConfigRead(_ context.Context, _ *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.configLock.RLock()
	defer b.configLock.RUnlock()

	return nonLockingRead(b)
}

func nonLockingRead(b *backend) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			keyRotationDuration: b.config.KeyRotationPeriod.String(),
			keyTokenTTL:         b.config.TokenTTL.String(),
			keySetIAT:           b.config.SetIAT,
			keySetJTI:           b.config.SetJTI,
			keySetNBF:           b.config.SetNBF,
			keyIssuer:           b.config.Issuer,
		},
	}, nil
}

const pathConfigHelpSyn = `
Configure the backend.
`

const pathConfigHelpDesc = `
Configure the backend.

key_ttl:          Duration before a key stops signing new tokens and a new one is generated.
		          After this period the public key will still be available to verify JWTs.
jwt_ttl:          Duration before a token expires.
set_iat:          Whether or not the backend should generate and set the 'iat' claim.
set_jti:          Whether or not the backend should generate and set the 'jti' claim.
set_nbf:          Whether or not the backend should generate and set the 'nbf' claim.
issuer:           Value to set as the 'iss' claim. Claim omitted if empty.
`
