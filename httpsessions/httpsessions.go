package httpsessions

import (
	"context"

	"github.com/39george/authpher"
	"github.com/alexedwards/scs/v2"
)

// ───── Concrete Session Store ───────────────────────────────────────────── //

type GoSessions struct {
	Store *scs.SessionManager
}

func (gs GoSessions) Get(ctx context.Context, key string) authpher.Data {
	d := gs.Store.Get(ctx, key)
	switch d.(type) {
	case authpher.Data:
		return d.(authpher.Data)
	default:
		return authpher.Data{}
	}
}
func (gs GoSessions) Set(ctx context.Context, k string, v authpher.Data) {
	gs.Store.Put(ctx, k, v)
}

// Not possible in gin
func (gs GoSessions) Save(ctx context.Context) {}

func (gs GoSessions) Clear(ctx context.Context) {
	gs.Store.Destroy(ctx)
}
