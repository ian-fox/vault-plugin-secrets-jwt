package jwtsecrets

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
)

const (
	keyKeys       = "keys"
	secretTypeKey = "rsa_key"
)

// signingKey holds a RSA key with a specified TTL.
type signingKey struct {
	Key *rsa.PrivateKey
	ID  string
}

func pathSecret(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", framework.GenericNameRegex("name"), keyKeys),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the key path.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathKeysRead,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathKeysDelete,
			},
		},
		HelpSynopsis:    pathKeysHelpSyn,
		HelpDescription: pathKeysHelpDesc,
	}
}

func secretKey(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretTypeKey,
		Fields: map[string]*framework.FieldSchema{
			"pem": {
				Type:        framework.TypeString,
				Description: "pem encoded string. Private key data.",
			},
			"id": {
				Type:        framework.TypeString,
				Description: "Private key ID.",
			},
		},
		Revoke: b.revokeKey,
	}
}

func (b *backend) pathKeysDelete(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	keyIDs, err := r.Storage.List(ctx, fmt.Sprintf("%s/", keysPath(name)))
	if err != nil {
		b.Logger().Error("Failed to list keys.", "error", err)
		return nil, err
	}

	for _, v := range keyIDs {
		err := r.Storage.Delete(ctx, fmt.Sprintf("%s/%s", keysPath(name), v))
		if err != nil {
			return logical.ErrorResponse("Failed to delete keys"), err
		}
	}
	return nil, nil
}

func (b *backend) pathKeysRead(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	key, err := b.getKey(ctx, name, r)
	if err != nil {
		b.Logger().Error("Failed to get keys.", "error", err)
		return logical.ErrorResponse("failed to get keys"), err
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key.Key)
	if err != nil {
		b.Logger().Error("Failed to get keys.", "error", err)
		return logical.ErrorResponse("marchal key to pkcs8"), err
	}

	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: pkcs8,
		},
	)

	secretD := map[string]interface{}{
		"pem": pem,
		"id":  key.ID,
	}
	internalD := map[string]interface{}{
		"key_id":    key.ID,
		"path_name": name,
	}

	resp := b.Secret(secretTypeKey).Response(secretD, internalD)
	resp.Secret.MaxTTL = b.config.MaxTTL

	return b.Secret(secretTypeKey).Response(secretD, internalD), nil
}

// getKey will return a valid key if one is available, or otherwise generate a new one.
func (b *backend) getKey(ctx context.Context, name string, r *logical.Request) (*signingKey, error) {
	key, err := b.getNewKey()
	if err != nil {
		return nil, errors.New("failed to generate new key")
	}
	entry, err := logical.StorageEntryJSON(fmt.Sprintf("%s/%s", keysPath(name), key.ID), key)
	if err != nil {
		return nil, err
	}
	err = r.Storage.Put(ctx, entry)
	if err != nil {
		return nil, err
	}

	return key, err
}

func (b *backend) getNewKey() (*signingKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	kid, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	newKey := &signingKey{
		ID:  kid.String(),
		Key: privateKey,
	}

	return newKey, nil
}

func (b *backend) revokeKey(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	keyID, ok := r.Secret.InternalData["key_id"]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing key ID")
	}
	name, ok := r.Secret.InternalData["path_name"]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing path name")
	}

	err := r.Storage.Delete(ctx, fmt.Sprintf("%s/%s", keysPath(name.(string)), keyID))
	if err != nil {
		return logical.ErrorResponse("Failed to delete key"), err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"key_id": keyID,
		},
	}, nil
}

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) getPublicKeys(ctx context.Context, name string, s logical.Storage) (*jose.JSONWebKeySet, error) {
	keyIDs, err := s.List(ctx, fmt.Sprintf("%s/", keysPath(name)))
	if err != nil {
		b.Logger().Error("Failed to list keys.", "error", err)
		return nil, err
	}
	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keyIDs)),
	}

	for i, v := range keyIDs {
		var key signingKey
		rawKey, err := s.Get(ctx, fmt.Sprintf("%s/%s", keysPath(name), v))
		if err != nil {
			b.Logger().Error("Failed to list keys.", "error", err)
			return nil, err
		}
		err = json.Unmarshal(rawKey.Value, &key)
		if err != nil {
			b.Logger().Error("Failed to unmarshal key.", "error", err)
			return nil, err
		}
		jwks.Keys[i].Key = &key.Key.PublicKey
		jwks.Keys[i].KeyID = key.ID
		jwks.Keys[i].Algorithm = "RS256"
		jwks.Keys[i].Use = "sig"
	}

	return &jwks, nil
}

// keysPath returns the formated keys path
func keysPath(name string) string {
	return fmt.Sprintf("%s/%s", name, keyKeys)
}

const pathKeysHelpSyn = `
Get RSA key pair.
`

const pathKeysHelpDesc = `
This path will return an RSA key pair. If no key pair previously existed a new one will be created.
The public key will only be remove after all usages of the private key are revoked.
`
