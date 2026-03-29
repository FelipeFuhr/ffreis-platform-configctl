package cmd

import (
	"context"

	"go.uber.org/zap"

	"github.com/ffreis/platform-configctl/internal/logger"
	"github.com/ffreis/platform-configctl/internal/store"
)

type noopLogger struct{}

func (noopLogger) Info(string, ...zap.Field)  {}
func (noopLogger) Warn(string, ...zap.Field)  {}
func (noopLogger) Error(string, ...zap.Field) {}
func (noopLogger) Debug(string, ...zap.Field) {}
func (noopLogger) With(...zap.Field) logger.Logger {
	return noopLogger{}
}

type fakeStore struct {
	listFn func(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error)
}

func (f fakeStore) Get(context.Context, string, string, store.ItemType, string) (*store.Item, error) {
	panic("unexpected store.Get call")
}
func (f fakeStore) Set(context.Context, *store.Item) error { panic("unexpected store.Set call") }
func (f fakeStore) List(ctx context.Context, project, env string, itemType store.ItemType) ([]*store.Item, error) {
	if f.listFn == nil {
		panic("unexpected store.List call")
	}
	return f.listFn(ctx, project, env, itemType)
}
func (f fakeStore) Delete(context.Context, string, string, store.ItemType, string) error {
	panic("unexpected store.Delete call")
}
func (f fakeStore) ListProjects(context.Context) ([]string, error) {
	panic("unexpected store.ListProjects call")
}
