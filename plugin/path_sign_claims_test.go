package jwtsecrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"gopkg.in/square/go-jose.v2/jwt"
)

func getSignedToken(b *backend, storage *logical.Storage, path string, dest interface{}) error {
	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      signClaimsPath(path),
		Storage:   *storage,
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

	if err = token.Claims(b.keys[0].Key.Public(), dest); err != nil {
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

	err := writeAndCheckClaims(b, storage, claimsPathA, claims, claims)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	var decoded jwt.Claims
	if err := getSignedToken(b, storage, claimsPathA, &decoded); err != nil {
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

func TestSignInvalidPath(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      signClaimsPath("non-existent"),
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil {
		t.Fatalf("%v\n", err)
	}
	if !resp.IsError() {
		t.Fatalf("call should have failed")
	}
}

type customToken struct {
	Foo string `json:"foo"`
}
