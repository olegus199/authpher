package authpher

import (
	"context"
	"crypto/subtle"
	"errors"
)

var (
	ErrUnauthorized = errors.New("unauthorized")
	ErrInternal     = errors.New("internal error")
	ErrForbidden    = errors.New("forbidden")
)

func AuthRun[P comparable, C any](
	ctx context.Context,
	store SessionStore,
	dataKey string,
	backend AuthzBackend[P, C],
) (*AuthSession[P, C], error) {
	data := store.Get(ctx, dataKey)
	authSession := AuthSession[P, C]{
		dataKey: dataKey,
		backend: backend,
		data:    data,
		session: store,
	}
	if data.UserId != nil {
		user, err := backend.GetUser(ctx, data.UserId)
		if err != nil {
			return nil, err
		}
		if user != nil &&
			subtle.ConstantTimeCompare(
				user.SessionAuthHash(),
				data.Hash,
			) == 1 {
			// Authorize
			authSession.User = user
		}
	}
	return &authSession, nil
}

func RequirePermission[P comparable, C any](
	ctx context.Context,
	permission P,
	authSession *AuthSession[P, C],
) error {
	if authSession.User == nil {
		return ErrUnauthorized
	}

	// On that stage backend and user are not nil
	has, err := hasPerm(
		ctx,
		authSession.backend,
		authSession.User,
		permission,
	)
	if err != nil {
		return ErrInternal
	}
	if !has {
		return ErrForbidden
	}
	return nil
}
