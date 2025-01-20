package authpher

import "context"

type Data struct {
	UserId any
	Hash   []byte
}

type SessionStore interface {
	Get(c context.Context, k string) Data
	Set(c context.Context, k string, v Data)
	Save(c context.Context)
	Clear(c context.Context)
}
