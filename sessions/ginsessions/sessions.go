package ginsessions

import (
	"github.com/39george/authpher"
	ginadapter "github.com/39george/scs_gin_adapter"
	"github.com/gin-gonic/gin"
)

type GinSessions struct {
	Store *ginadapter.GinAdapter
}

func (gs GinSessions) Get(ctx *gin.Context, key string) authpher.Data {
	d := gs.Store.Get(ctx, key)
	switch d.(type) {
	case authpher.Data:
		return d.(authpher.Data)
	default:
		return authpher.Data{}
	}
}
func (gs GinSessions) Set(ctx *gin.Context, k string, v authpher.Data) {
	gs.Store.Put(ctx, k, v)
}

// Not possible in gin
func (gs GinSessions) Save(ctx *gin.Context) {}

func (gs GinSessions) Clear(ctx *gin.Context) {
	gs.Store.Destroy(ctx)
}
