package jwtsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathJwks(b *backend) *framework.Path {
	return &framework.Path{
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Path name.",
			},
		},
		Pattern: fmt.Sprintf("%s/%s", framework.GenericNameRegex("name"), "jwks"),
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathJwksRead,
			},
		},

		HelpSynopsis:    pathJwksHelpSyn,
		HelpDescription: pathJwksHelpDesc,
	}
}

func (b *backend) pathJwksRead(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	keys, err := b.getPublicKeys(ctx, name, r.Storage)
	if err != nil {
		b.Logger().Error("Failed to get jwks.", "error", err)
		return logical.ErrorResponse("failed to get keys"), nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"keys": keys.Keys,
		},
	}, nil
}

const pathJwksHelpSyn = `
Get a JSON Web Key Set.
`

const pathJwksHelpDesc = `
Get a JSON Web Key Set.
`
