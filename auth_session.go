package authpher

import (
	"context"
	"fmt"
)

// AuthSession, user-interaction type
type AuthSession[P comparable, C any] struct {
	User    AuthUser
	backend AuthzBackend[P, C]
	data    Data
	dataKey string
	session SessionStore
}

// Verifies the provided credentials via the backend returning the
// authenticated user if valid and otherwise `nil`.
func (aS *AuthSession[T, C]) Authenticate(
	ctx context.Context,
	creds C,
) (AuthUser, error) {
	return aS.backend.Authenticate(ctx, creds)
}

// Updates the session such that the user is logged in.
func (aS *AuthSession[P, C]) Login(c context.Context, user AuthUser) error {
	if user == nil {
		return fmt.Errorf("user shouldn't be nil")
	}

	aS.User = user

	if len(aS.data.Hash) == 0 {
		// TODO: perform session-fixation mitigation
		// Prevent session fixation attacks by ensuring a
		// new ID is assigned to the session.
	}

	aS.data.UserId = user.UserId()
	aS.data.Hash = user.SessionAuthHash()

	// Update session
	aS.session.Set(c, aS.dataKey, aS.data)
	aS.session.Save(c)
	return nil
}

// Updates the session such that the user is logged out.
func (aS *AuthSession[T, C]) Logout(c context.Context) AuthUser {
	user := aS.User
	aS.User = nil

	aS.session.Clear(c)

	return user
}
