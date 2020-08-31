package jwtsecrets

import (
	"context"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	claimsPathA = "pathA"
	claimsPathB = "pathB"
)

func claimsA() map[string]string {
	return map[string]string{
		"iss": "pathA",
	}
}

func claimsB() map[string]string {
	return map[string]string{
		"iss": "pathB",
		"sub": "test",
	}
}

func TestWriteClaims(t *testing.T) {
	b, storage := getTestBackend(t)

	dataA := map[string]interface{}{
		"claims": claimsA(),
	}
	err := writeAndCheckClaims(b, storage, dataA, claimsA())
	if err != nil {
		t.Error(err)
	}

	dataB := map[string]interface{}{
		"claims": claimsA(),
	}
	err = writeAndCheckClaims(b, storage, dataB, claimsB())
	if err != nil {
		t.Error(err)
	}
}

func TestReadClaims(t *testing.T) {
	b, storage := getTestBackend(t)

	dataA := map[string]interface{}{
		"claims": claimsA(),
	}
	err := writeAndCheckClaims(b, storage, dataA, claimsA())
	if err != nil {
		t.Error(err)
	}

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      claimsPath(claimsPathA),
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Error(err)
	}

	claims := resp.Data[keyClaims].(map[string]string)
	if diff := deep.Equal(claimsA(), claims); diff != nil {
		t.Error(err)
	}
}

func writeAndCheckClaims(b *backend, storage *logical.Storage, data map[string]interface{}, expected map[string]string) error {
	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      claimsPath(claimsPathA),
		Storage:   *storage,
		Data:      data,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		return err
	}

	claims := resp.Data[keyClaims].(map[string]string)

	if diff := deep.Equal(claimsA(), claims); diff != nil {
		return err
	}
	return nil
}
