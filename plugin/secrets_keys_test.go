package jwtsecrets

import (
	"context"
	"testing"
	"time"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/assert"
)

const (
	pathA = "pathA"
	pathB = "pathB"
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
}

func TestGetExistingKey(t *testing.T) {
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

	if diff := deep.Equal(respA.Data["pem"], respB.Data["pem"]); diff != nil {
		t.Error("Keys must be the same until rotated")
	}
	if diff := deep.Equal(respA.Data["id"], respB.Data["id"]); diff != nil {
		t.Error("Key ids must be the same until rotated")
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

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathC"),
		Storage:   *storage,
	}

	respB, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	if diff := deep.Equal(respA.Data["pem"], respB.Data["pem"]); diff == nil {
		t.Error("Keys should have been rotated")
	}
	if diff := deep.Equal(respA.Data["id"], respB.Data["id"]); diff == nil {
		t.Error("Keys should have been rotated")
	}
}

func TestExpiringKeys(t *testing.T) {
	b, storage := getTestBackend(t)
	b.config.KeyRotationPeriod, _ = time.ParseDuration("1m")
	b.config.TokenTTL, _ = time.ParseDuration("2m")

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathC"),
		Storage:   *storage,
	}

	respA, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathC"),
		Storage:   *storage,
	}

	respB, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	if diff := deep.Equal(respA.Data["pem"], respB.Data["pem"]); diff == nil {
		t.Error("Keys should have been rotated")
	}
	if diff := deep.Equal(respA.Data["id"], respB.Data["id"]); diff == nil {
		t.Error("Keys should have been rotated")
	}
}

func TestRotateKeys(t *testing.T) {
	b, storage := getTestBackend(t)
	b.config.KeyRotationPeriod, _ = time.ParseDuration("0s")

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathC"),
		Storage:   *storage,
	}

	respA, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	req = &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathC"),
		Storage:   *storage,
	}

	respB, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)

	if diff := deep.Equal(respA.Data["pem"], respB.Data["pem"]); diff == nil {
		t.Error("Keys should have been rotated")
	}
	if diff := deep.Equal(respA.Data["id"], respB.Data["id"]); diff == nil {
		t.Error("Keys should have been rotated")
	}
}

func TestDeleteKey(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      keysPath("pathA"),
		Storage:   *storage,
	}

	respA, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.NotEmpty(t, respA.Data)
	l, _ := req.Storage.List(context.Background(), "pathA")
	assert.NotEmpty(t, l)

	req = &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      keysPath("pathA"),
		Storage:   *storage,
	}

	respB, err := b.HandleRequest(context.Background(), req)
	assert.NoError(t, err, "Should not error")
	assert.Empty(t, respB)
	l, _ = req.Storage.List(context.Background(), "pathA")
	assert.Empty(t, l)
}
