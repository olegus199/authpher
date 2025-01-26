package ginsessions

import (
	"context"

	"github.com/39george/authpher"
	ginadapter "github.com/39george/scs_gin_adapter"
	"github.com/gin-gonic/gin"
)

type GinSessions struct {
	Store *ginadapter.GinAdapter
}

func (gs GinSessions) Get(ctx context.Context, key string) authpher.Data {
	c := ctx.(*gin.Context)
	d := gs.Store.Get(c, key)
	switch d := d.(type) {
	case authpher.Data:
		return d
	default:
		return authpher.Data{}
	}
}
func (gs GinSessions) Set(ctx context.Context, k string, v authpher.Data) {
	c := ctx.(*gin.Context)
	gs.Store.Put(c, k, v)
}

// Not possible in gin
func (gs GinSessions) Save(ctx context.Context) {}

func (gs GinSessions) Clear(ctx context.Context) {
	c := ctx.(*gin.Context)
	gs.Store.Destroy(c)
}
