package testbackend

import (
	"context"
	"errors"

	mapset "github.com/deckarep/golang-set/v2"

	"github.com/39george/authpher"
)

type TestUser struct {
	ID           int32
	Username     string
	PasswordHash string
}

func (tu TestUser) UserId() any {
	return tu.ID

}

func (tu TestUser) SessionAuthHash() []byte {
	return []byte(tu.PasswordHash)
}

type TestCredentials struct {
	Username string
	Password string
}

type TestBackend struct {
}

func (mb TestBackend) Authenticate(
	ctx context.Context,
	creds TestCredentials,
) (authpher.AuthUser, error) {
	shouldBe := TestCredentials{Username: "testuser", Password: "testpassword"}
	if creds == shouldBe {
		return &TestUser{123, "testuser", "testpasswordhash"}, nil
	} else {
		return nil, errors.New("Bad credentials")
	}
}

func (mb TestBackend) GetUser(
	ctx context.Context,
	userId any,
) (authpher.AuthUser, error) {
	usrId := userId.(int32)
	if usrId == 123 {
		return &TestUser{123, "testuser", "testpasswordhash"}, nil
	} else {
		return nil, errors.New("bad user id")
	}
}

func (mb TestBackend) GetUserPermissions(
	ctx context.Context,
	user authpher.AuthUser,
) (mapset.Set[string], error) {
	perms := mapset.NewSet[string]()
	// Cast to TestUser.ID type
	if user.UserId().(int32) == 123 {
		perms.Add("userpermission")
	}
	return perms, nil
}

func (mb TestBackend) GetGroupPermissions(
	ctx context.Context,
	user authpher.AuthUser,
) (mapset.Set[string], error) {
	perms := mapset.NewSet[string]()
	return perms, nil
}
