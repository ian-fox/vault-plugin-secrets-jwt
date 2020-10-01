package jwtsecrets

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

func TestGetNewKey(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathA"),
		Storage:   *storage,
	}

	respA, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathB"),
		Storage:   *storage,
	}

	respB, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respB.Data)

	if diff := deep.Equal(respA.Data["pem"], respB.Data["pem"]); diff == nil {
		t.Error("Keys for different paths must be unique")
	}
	if diff := deep.Equal(respA.Data["id"], respB.Data["id"]); diff == nil {
		t.Error("Key ids for different paths must be unique")
	}

	// Check if pem correspond to original key
	block, _ := pem.Decode([]byte(respB.Data["pem"].([]byte)))
	assert.NotEmpty(t, block)
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	assert.NoError(t, err, "Should not error")

	rawKey, err := req.Storage.Get(context.Background(), fmt.Sprintf("%s/%s", keysPath("pathB"), respB.Data["id"]))
	assert.NoError(t, err, "Should not error")
	var key rsa.PrivateKey
	err = json.Unmarshal(rawKey.Value, &key)
	assert.NoError(t, err, "Should not error")
	if diff := deep.Equal(key, priv); diff == nil {
		t.Error("Key ids for different paths must be unique")
	}
}

func TestGetNewKeySamePath(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathA"),
		Storage:   *storage,
	}

	respA, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathA"),
		Storage:   *storage,
	}

	respB, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respB.Data)

	if diff := deep.Equal(respA.Data["pem"], respB.Data["pem"]); diff == nil {
		t.Error("Keys for different paths must be unique")
	}
	if diff := deep.Equal(respA.Data["id"], respB.Data["id"]); diff == nil {
		t.Error("Key ids for different paths must be unique")
	}
}

func TestRevokeKeys(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathC"),
		Storage:   *storage,
	}

	respA, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    respA.Secret,
		Storage:   *storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}

	l, _ := req.Storage.List(context.Background(), "pathC")
	assert.Empty(t, l)
}

func TestDeleteKey(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathD"),
		Storage:   *storage,
	}

	respA, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)
	l, _ := req.Storage.List(context.Background(), keysPath("pathD"))
	assert.NotEmpty(t, l)

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      keysPath("pathD"),
		Storage:   *storage,
	}

	respB, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.Empty(t, respB)
	l, _ = req.Storage.List(context.Background(), keysPath("pathD"))
	assert.Empty(t, l)
}
