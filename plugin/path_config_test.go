package jwtsecrets

import (
	"context"
	"testing"

	"github.com/go-test/deep"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	updatedTTL = "6m0s"
	newIssuer  = "new-vault"
)

func TestDefaultConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "config",
		Storage:   *storage,
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	tokenTTL := resp.Data[keyTokenTTL].(string)

	if diff := deep.Equal(DefaultTokenTTL, tokenTTL); diff != nil {
		t.Error(diff)
	}
}

func TestWriteConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   *storage,
		Data: map[string]interface{}{
			keyTokenTTL: updatedTTL,
			keySetIAT:   false,
			keySetJTI:   false,
			keySetNBF:   false,
			keyIssuer:   newIssuer,
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("err:%s resp:%#v\n", err, resp)
	}

	tokenTTL := resp.Data[keyTokenTTL].(string)
	setIAT := resp.Data[keySetIAT].(bool)
	setJTI := resp.Data[keySetJTI].(bool)
	setNBF := resp.Data[keySetNBF].(bool)
	issuer := resp.Data[keyIssuer].(string)

	if diff := deep.Equal(updatedTTL, tokenTTL); diff != nil {
		t.Error("expiry period should be unchanged:", diff)
	}

	if diff := deep.Equal(false, setIAT); diff != nil {
		t.Error("expected set_iat to be false")
	}

	if diff := deep.Equal(false, setJTI); diff != nil {
		t.Error("expected set_jti to be false")
	}

	if diff := deep.Equal(false, setNBF); diff != nil {
		t.Error("expected set_nbf to be false")
	}

	if diff := deep.Equal(newIssuer, issuer); diff != nil {
		t.Error("unexpected issuer:", diff)
	}
}

func TestWriteInvalidConfig(t *testing.T) {
	b, storage := getTestBackend(t)

	req := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   *storage,
		Data: map[string]interface{}{
			keyTokenTTL: "not a real duration",
		},
	}

	resp, err := b.HandleRequest(context.Background(), req)
	if err == nil {
		t.Errorf("Should have errored but got response: %#v", resp)
	}
}
