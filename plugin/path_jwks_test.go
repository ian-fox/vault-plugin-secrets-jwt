package jwtsecrets

import (
	"context"
	"fmt"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

func TestEmptyJwks(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "pathA/jwks",
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	typedKeys, ok := resp.Data["keys"].([]jose.JSONWebKey)
	if !ok {
		t.Fatalf("Expected keys to be of type %T. Instead got %T", jose.JSONWebKey{}, resp.Data["keys"])
	}

	if len(typedKeys) != 0 {
		t.Errorf("Expected %v to be an array of length 0.", typedKeys)
	}
}

func TestJwks(t *testing.T) {
	b, storage := getTestBackend(t)

	// Cause it to generate a key
	claims := map[string]interface{}{
		"claims": map[string]interface{}{
			"aud": "Zapp Brannigan",
		},
	}

	var decoded jwt.Claims
	if err := getSignedToken(b, storage, pathA, claims, &decoded); err != nil {
		t.Fatalf("%v\n", err)
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      fmt.Sprintf("%s/%s", pathA, "jwks"),
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	rawKeys, ok := resp.Data["keys"]
	if !ok {
		t.Fatalf("No returned keys.")
	}

	typedKeys, ok := rawKeys.([]jose.JSONWebKey)
	if !ok {
		t.Fatalf("JWKS was not a %T", []jose.JSONWebKey{})
	}

	expectedKeys, err := b.getPublicKeys(context.Background(), pathA, *storage)
	assert.NoError(t, err, "Should not error")

	if len(expectedKeys.Keys) == 0 {
		t.Fatal("Expected at least one key to be present.")
	}

	if diff := deep.Equal(expectedKeys.Keys, typedKeys); diff != nil {
		t.Error(diff)
	}
}
