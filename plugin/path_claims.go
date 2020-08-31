package jwtsecrets

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	keyClaims           = "claims"
	claimsStoragePrefix = "claims"
)

func pathClaims(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", claimsStoragePrefix, framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the custom claims set.",
			},
			"claims": {
				Type:        framework.TypeKVPairs,
				Description: "Required. The map of custom claims.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathClaimsWrite,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathClaimsWrite,
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathClaimsRead,
			},
		},
		HelpSynopsis:    pathClaimsHelpSyn,
		HelpDescription: pathClaimsHelpDesc,
	}
}

func (b *backend) pathClaimsWrite(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.claimsLock.Lock()
	defer b.claimsLock.Unlock()

	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	claims, err := getClaims(ctx, name, r.Storage)
	if err != nil {
		return nil, err
	}

	if claims == nil {
		if c, ok := d.GetOk(keyClaims); ok {
			claims = c.(map[string]string)
		}
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", claimsStoragePrefix, name), claims)
	if err != nil {
		return nil, err
	}
	err = r.Storage.Put(ctx, entry)
	if err != nil {
		return logical.ErrorResponse("Failed to save claim"), err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			keyClaims: claims,
		},
	}, nil
}

func (b *backend) pathClaimsRead(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	claims, err := getClaims(ctx, name, r.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			keyClaims: claims,
		},
	}, nil
}

func getClaims(ctx context.Context, name string, s logical.Storage) (map[string]string, error) {
	entry, err := s.Get(ctx, claimsPath(name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	c := map[string]string{}
	if err := entry.DecodeJSON(&c); err != nil {
		return nil, err
	}
	return c, nil
}

// claimsPath returns the formated claims path
func claimsPath(name string) string {
	return fmt.Sprintf("%s/%s", claimsStoragePrefix, name)
}

const pathClaimsHelpSyn = `
Configure a custom claim set.
`

const pathClaimsHelpDesc = `
Configure the custom claims set.

claims:  Map of custom claims.
`
