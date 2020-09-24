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
	sigClaimsStoragePrefix = "sign"
)

func pathSignClaims(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: fmt.Sprintf("%s/%s", sigClaimsStoragePrefix, framework.GenericNameRegex("name")),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Required. Name of the custom claims set.",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathSignClaimsRead,
			},
		},
		HelpSynopsis:    pathSignClaimsHelpSyn,
		HelpDescription: pathSignClaimsHelpDesc,
	}
}

func (b *backend) pathSignClaimsRead(ctx context.Context, r *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	nameRaw, ok := d.GetOk("name")
	if !ok {
		return logical.ErrorResponse("name is required"), nil
	}
	name := nameRaw.(string)

	claims, err := b.getClaims(ctx, name, r.Storage)
	if err != nil {
		return logical.ErrorResponse(err.Error()), err
	}

	if claims == nil {
		return logical.ErrorResponse("claims not set"), err
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

	key, err := b.getKey(ctx, name, r.Storage)
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

// claimsPath returns the formated claims path
func signClaimsPath(name string) string {
	return fmt.Sprintf("%s/%s", sigClaimsStoragePrefix, name)
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

const pathSignClaimsHelpSyn = `
Signs a set of preconfigured claims.
`

const pathSignClaimsHelpDesc = `
Signs a set of preconfigured claims.
`
