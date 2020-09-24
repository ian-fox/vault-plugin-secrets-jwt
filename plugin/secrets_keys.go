package jwtsecrets

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
)

const (
	keyKeys = "keys"
)

// signingKey holds a RSA key with a specified TTL.
type signingKey struct {
	// Usage counts number of revokes instances using the secret
	Usage    int
	UseUntil time.Time
	Key      *rsa.PrivateKey
	ID       string
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
		},
		HelpSynopsis:    pathKeysHelpSyn,
		HelpDescription: pathKeysHelpDesc,
	}
}

func (b *backend) pathKeysRead(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	key, err := b.getKey(ctx, name, r.Storage)
	if err != nil {
		return logical.ErrorResponse("failed to get keys"), nil
	}

	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key.Key),
		},
	)

	return &logical.Response{
		Data: map[string]interface{}{
			"pem":    pem,
			"id":     key.ID,
			"usage":  key.Usage,
			"rotate": key.UseUntil,
		},
	}, nil
}

// getKey will return a valid key if one is available, or otherwise generate a new one.
func (b *backend) getKey(ctx context.Context, name string, s logical.Storage) (*signingKey, error) {
	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	keys, err := b.getKeys(ctx, name, s)
	if err != nil {
		return nil, errors.New("Failed to load keys")
	}
	key, err := b.getExistingKey(keys)
	if err != nil {
		key, err = b.getNewKey()
		if err != nil {
			return nil, errors.New("failed to generate new key")
		}
		keys = append(keys, key)
	}
	err = b.saveKeys(ctx, name, keys, s)
	return key, err
}

func (b *backend) saveKeys(ctx context.Context, name string, keys []*signingKey, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(keysPath(name), keys)
	if err != nil {
		return err
	}
	err = s.Put(ctx, entry)
	if err != nil {
		return err
	}
	return nil
}

func (b *backend) getKeys(ctx context.Context, name string, s logical.Storage) ([]*signingKey, error) {
	entry, err := s.Get(ctx, keysPath(name))
	keys := make([]*signingKey, 0)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return keys, nil
	}
	if err := entry.DecodeJSON(&keys); err != nil {
		return nil, err
	}

	return keys, nil
}

func (b *backend) getExistingKey(keys []*signingKey) (*signingKey, error) {
	now := b.clock.now()
	for _, k := range keys {
		if k.UseUntil.After(now) {
			return k, nil
		}
	}
	return nil, errors.New("no valid key found")
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

	rotationTime := b.clock.now().Add(b.config.KeyRotationPeriod)

	newKey := &signingKey{
		ID:       kid.String(),
		Key:      privateKey,
		UseUntil: rotationTime,
	}

	return newKey, nil
}

func (b *backend) pruneOldKeys(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//TODO: put in revoke function
	b.keysLock.RLock()
	defer b.keysLock.RUnlock()
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	keys, err := b.getKeys(ctx, name, r.Storage)
	if err != nil {
		return nil, err
	}

	n := 0
	for _, k := range keys {
		if k.Usage > 0 {
			b.keys[n] = k
			n++
		}
	}
	b.keys = b.keys[:n]

	return nil, nil
}

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) getPublicKeys(ctx context.Context, name string, s logical.Storage) (*jose.JSONWebKeySet, error) {
	keys, err := b.getKeys(ctx, name, s)
	if err != nil {
		return nil, err
	}

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(b.keys)),
	}

	for i, k := range keys {
		jwks.Keys[i].Key = &k.Key.PublicKey
		jwks.Keys[i].KeyID = k.ID
		jwks.Keys[i].Algorithm = "RS256"
		jwks.Keys[i].Use = "sig"
	}

	return &jwks, nil
}

// claimsPath returns the formated keys path
func keysPath(name string) string {
	return fmt.Sprintf("%s/%s", name, keyKeys)
}

const pathKeysHelpSyn = `
Get RSA key pair.
`

const pathKeysHelpDesc = `
This path will return an RSA key pair. If no key pair previously existed a new one will be created and the usage will be tracked by the token accessor.
`
