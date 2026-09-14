package main

import (
	"context"

	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/logger"
	"github.com/ffreis/platform-configctl/internal/store"
)

const testSecretKey = "01234567890123456789012345678901"

type noopLogger struct{}

func (noopLogger) Info(string, ...zap.Field)  {}
func (noopLogger) Warn(string, ...zap.Field)  {}
func (noopLogger) Error(string, ...zap.Field) {}
func (noopLogger) Debug(string, ...zap.Field) {}
func (noopLogger) With(...zap.Field) logger.Logger {
	return noopLogger{}
}

type fakeStore struct {
	getFn    func(ctx context.Context, project, env string, itemType store.ItemType, key string) (*store.Item, error)
	setFn    func(ctx context.Context, item *store.Item) error
	listFn   func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error)
	deleteFn func(ctx context.Context, project, env string, itemType store.ItemType, key string) error
}

func (f fakeStore) Get(ctx context.Context, project, env string, itemType store.ItemType, key string) (*store.Item, error) {
	if f.getFn == nil {
		panic("unexpected store.Get call")
	}
	return f.getFn(ctx, project, env, itemType, key)
}
func (f fakeStore) Set(ctx context.Context, item *store.Item) error {
	if f.setFn == nil {
		panic("unexpected store.Set call")
	}
	return f.setFn(ctx, item)
}
func (f fakeStore) List(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
	if f.listFn == nil {
		panic("unexpected store.List call")
	}
	return f.listFn(ctx, project, env, itemType)
}
func (f fakeStore) Delete(ctx context.Context, project, env string, itemType store.ItemType, key string) error {
	if f.deleteFn == nil {
		panic("unexpected store.Delete call")
	}
	return f.deleteFn(ctx, project, env, itemType, key)
}
func (f fakeStore) ListProjects(context.Context) ([]string, error) {
	panic("unexpected store.ListProjects call")
}

// encryptedVaultItem builds a real, tier-bound-AAD encrypted store.Item for
// key, exactly as runPut would produce, for tests that need a real
// ciphertext to decrypt through runGet/runExec/runExportEnv.
func encryptedVaultItem(tier, env, key, plaintext string) *store.Item {
	ciphertext, keyID, err := encryptVaultValue(testSecretKey, tier, env, key, []byte(plaintext))
	if err != nil {
		panic(err)
	}
	return &store.Item{Key: key, Value: string(ciphertext), KeyID: keyID, Version: 1}
}
