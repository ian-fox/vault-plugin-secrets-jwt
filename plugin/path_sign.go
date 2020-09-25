package jwtsecrets

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

const (
	signStoragePrefix = "sign"
)

func pathSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", framework.GenericNameRegex("name"), signStoragePrefix),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the custom claims set.",
			},
			"claims": {
				Type:        framework.TypeMap,
				Description: `JSON claim set to sign.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathSignWrite,
			},
		},
		HelpSynopsis:    pathSignHelpSyn,
		HelpDescription: pathSignHelpDesc,
	}
}

func (b *backend) pathSignWrite(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)
	rawClaims, ok := d.GetOk("claims")
	if !ok {
		return logical.ErrorResponse("no claims provided"), logical.ErrInvalidRequest
	}
	claims, ok := rawClaims.(map[string]interface{})
	if !ok {
		return logical.ErrorResponse("claims not a map"), logical.ErrInvalidRequest
	}

	config := *b.config
	now := b.clock.now()

	expiry := now.Add(config.TokenTTL)
	claims["exp"] = jwt.NumericDate(expiry.Unix())

	if config.SetIAT {
		claims["iat"] = jwt.NumericDate(now.Unix())
	}

	if config.SetNBF {
		claims["nbf"] = jwt.NumericDate(now.Unix())
	}

	if config.SetJTI {
		jti, err := b.uuidGen.uuid()
		if err != nil {
			return logical.ErrorResponse("could not generate 'jti' claim: %v", err), err
		}
		claims["jti"] = jti
	}

	key, err := b.getKey(ctx, name, r)
	if err != nil {
		return logical.ErrorResponse("failed to get keys"), nil
	}

	token, err := sign(key, expiry, claims)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"token": token,
		},
	}, nil
}

// signPath returns the formated claims path
func signPath(name string) string {
	return fmt.Sprintf("%s/%s", name, signStoragePrefix)
}

func sign(key *signingKey, expiry time.Time, claims map[string]interface{}) (string, error) {
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key.Key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", key.ID))
	if err != nil {
		return "", errors.New("error signing claims: " + err.Error())
	}

	token, err := jwt.Signed(sig).Claims(claims).CompactSerialize()
	if err != nil {
		return "", errors.New("error serializing jwt: " + err.Error())
	}

	return token, nil
}

const pathSignHelpSyn = `
Signs a set of claims with the private the of the specified path.
`

const pathSignHelpDesc = `
Signs a set of claims with the private the of the specified path. Example:

vault write jwt/key_path/sign @claims.json

claims.json:
{
	"claims": {
			"sub": "Zapp Brannigan"
	}
}
`
