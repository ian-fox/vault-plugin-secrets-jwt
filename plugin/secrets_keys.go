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
	keyKeys       = "keys"
	secretTypeKey = "rsa_key"
)

type keyStorage struct {
	KeyUsage map[string]string      `json:"key_usage"`
	Keys     map[string]*signingKey `json:"keys"`
}

// signingKey holds a RSA key with a specified TTL.
type signingKey struct {
	UseCount int
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

func (b *backend) pathKeysRead(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	key, err := b.getKey(ctx, name, r)
	if err != nil {
		return logical.ErrorResponse("failed to get keys"), nil
	}

	pem := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(key.Key),
		},
	)

	secretD := map[string]interface{}{
		"pem": pem,
		"id":  key.ID,
	}
	internalD := map[string]interface{}{
		"request_id": r.ID,
		"path_name":  name,
	}

	return b.Secret(secretTypeKey).Response(secretD, internalD), nil
}

// getKey will return a valid key if one is available, or otherwise generate a new one.
func (b *backend) getKey(ctx context.Context, name string, r *logical.Request) (*signingKey, error) {
	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	s := r.Storage
	keyStorage, err := b.getKeyStorage(ctx, name, s)
	if err != nil {
		return nil, errors.New("Failed to load keys")
	}
	key, err := b.getExistingKey(keyStorage)
	if err != nil {
		key, err = b.getNewKey()
		if err != nil {
			return nil, errors.New("failed to generate new key")
		}
		keyStorage.Keys[key.ID] = key
	}
	keyStorage.KeyUsage[r.ID] = key.ID
	key.UseCount++
	err = b.saveKeys(ctx, name, keyStorage, s)
	return key, err
}

func (b *backend) saveKeys(ctx context.Context, name string, keyStorage *keyStorage, s logical.Storage) error {
	entry, err := logical.StorageEntryJSON(keysPath(name), *keyStorage)
	if err != nil {
		return err
	}
	err = s.Put(ctx, entry)
	if err != nil {
		return err
	}
	return nil
}

func (b *backend) getKeyStorage(ctx context.Context, name string, s logical.Storage) (*keyStorage, error) {
	entry, err := s.Get(ctx, keysPath(name))
	keyStorage := &keyStorage{
		KeyUsage: make(map[string]string, 4),
		Keys:     make(map[string]*signingKey, 4),
	}
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return keyStorage, nil
	}
	if err := entry.DecodeJSON(keyStorage); err != nil {
		return nil, err
	}

	return keyStorage, nil
}

func (b *backend) getExistingKey(keyStorage *keyStorage) (*signingKey, error) {
	now := b.clock.now()
	for _, v := range keyStorage.Keys {
		if v.UseUntil.After(now) {
			return v, nil
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

func (b *backend) revokeKey(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.keysLock.RLock()
	defer b.keysLock.RUnlock()

	reqID, ok := r.Secret.InternalData["request_id"]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing request ID")
	}
	name, ok := r.Secret.InternalData["path_name"]
	if !ok {
		return nil, fmt.Errorf("invalid secret, internal data is missing path name")
	}

	keyStorage, err := b.getKeyStorage(ctx, name.(string), r.Storage)
	if err != nil {
		return nil, err
	}

	keyID, ok := keyStorage.KeyUsage[reqID.(string)]
	delete(keyStorage.KeyUsage, reqID.(string))
	if !ok {
		return logical.ErrorResponse("failed to revoke key"), nil
	}
	keyStorage.Keys[keyID].UseCount--

	if keyStorage.Keys[keyID].UseCount == 0 {
		delete(keyStorage.Keys, keyID)
	}
	err = b.saveKeys(ctx, name.(string), keyStorage, r.Storage)
	if err != nil {
		return nil, err
	}

	return nil, nil
}

// GetPublicKeys returns a set of JSON Web Keys.
func (b *backend) getPublicKeys(ctx context.Context, name string, s logical.Storage) (*jose.JSONWebKeySet, error) {
	keyStorage, err := b.getKeyStorage(ctx, name, s)
	if err != nil {
		return nil, err
	}

	jwks := jose.JSONWebKeySet{
		Keys: make([]jose.JSONWebKey, len(keyStorage.Keys)),
	}

	i := 0
	for _, v := range keyStorage.Keys {
		jwks.Keys[i].Key = &v.Key.PublicKey
		jwks.Keys[i].KeyID = v.ID
		jwks.Keys[i].Algorithm = "RS256"
		jwks.Keys[i].Use = "sig"
		i++
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
This path will return an RSA key pair. If no key pair previously existed a new one will be created.
The public key will only be remove after all usages of the private key are revoked.
`
