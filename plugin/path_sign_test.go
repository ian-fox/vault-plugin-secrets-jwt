package jwtsecrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2/jwt"
)

func getSignedToken(b *backend, storage *logical.Storage, path string, claims map[string]interface{}, dest interface{}) error {
	req := &logical.Request{
		Operation: logical.CreateOperation,
		Path:      signPath(path),
		Storage:   *storage,
		Data:      claims,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		return fmt.Errorf("err:%s resp:%#v", err, resp)
	}

	rawToken, ok := resp.Data["token"]
	if !ok {
		return fmt.Errorf("no returned token")
	}

	strToken, ok := rawToken.(string)
	if !ok {
		return fmt.Errorf("Token was %T, not a string", rawToken)
	}

	token, err := jwt.ParseSigned(strToken)
	if err != nil {
		return fmt.Errorf("error parsing jwt: %s", err)
	}

	key, err := b.getKey(context.Background(), path, req)
	if err != nil {
		return err
	}
	if err = token.Claims(key.Key.Public(), dest); err != nil {
		return fmt.Errorf("error decoding claims: %s", err)
	}

	return nil
}

func TestSign(t *testing.T) {
	b, storage := getTestBackend(t)

	claims := map[string]interface{}{
		"claims": map[string]interface{}{
			"aud": "Zapp Brannigan",
		},
	}

	var decoded jwt.Claims
	if err := getSignedToken(b, storage, pathA, claims, &decoded); err != nil {
		t.Fatalf("%v\n", err)
	}

	expectedExpiry := jwt.NumericDate(5 * 60)
	expectedIssuedAt := jwt.NumericDate(0)
	expectedNotBefore := jwt.NumericDate(0)
	expectedClaims := jwt.Claims{
		Audience:  []string{"Zapp Brannigan"},
		Expiry:    &expectedExpiry,
		IssuedAt:  &expectedIssuedAt,
		NotBefore: &expectedNotBefore,
		ID:        "1",
		Issuer:    testIssuer,
	}

	if diff := deep.Equal(expectedClaims, decoded); diff != nil {
		t.Error(diff)
	}
}
