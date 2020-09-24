package jwtsecrets

import (
	"context"
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

func TestGetRotatedKey(t *testing.T) {

}

func TestRevokeKeys(t *testing.T) {

}
