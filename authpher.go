package authpher

import (
	"context"

	mapset "github.com/deckarep/golang-set/v2"
)

const AuthContextString = "userLoginAuthSession"

// Authenticating user type.
type AuthUser interface {
	// Returns some identifying feature of the user.
	UserId() any

	// Returns a hash that's used by the session to verify the session is
	// valid.
	//
	// For example, if users have passwords, this method might return a
	// cryptographically secure hash of that password.
	SessionAuthHash() []byte
}

// A backend which can authenticate users.
//
// Backends must implement:
//
//  1. [AuthnBackend.Authenticate], a method for authenticating
//     users with credentials and,
//  2. [AuthnBackend.GetUser] a method for getting a user by an
//     identifying feature.
//
// With these two methods, users may be authenticated and later retrieved via
// the backend.
type AuthnBackend[C any] interface {
	// Authenticates the given credentials with the backend.
	Authenticate(ctx context.Context, creds C) (AuthUser, error)
	// Gets the user by provided ID from the backend.
	GetUser(ctx context.Context, userId any) (AuthUser, error)
}

// A backend which can authorize users.
//
// Backends must implement [AuthnBackend].
type AuthzBackend[P comparable, C any] interface {
	AuthnBackend[C]
	// Gets the permissions for the provided user.
	GetUserPermissions(
		ctx context.Context,
		user AuthUser,
	) (mapset.Set[P], error)
	// Gets the group permissions for the provided user.
	GetGroupPermissions(
		ctx context.Context,
		user AuthUser,
	) (mapset.Set[P], error)
}

// Returns a result which is `true` when the provided user has the provided
// permission and otherwise is `false`.
//
//	`b`: can't be nil
//	`user`: can't be nil
func hasPerm[P comparable, C any](
	ctx context.Context,
	b AuthzBackend[P, C],
	user AuthUser,
	perm P,
) (bool, error) {
	group, err := b.GetGroupPermissions(ctx, user)
	if err != nil {
		return false, err
	}
	usr, err := b.GetUserPermissions(ctx, user)
	if err != nil {
		return false, err
	}
	return group.Union(usr).Contains(perm), nil
}
