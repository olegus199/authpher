package authgin_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"testing"
	"time"

	ginAdapter "github.com/39george/scs_gin_adapter"
	scsRedisStore "github.com/39george/scs_redisstore"
	"github.com/alexedwards/scs/v2"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/39george/authpher"
	"github.com/39george/authpher/adapters/authgin"
	"github.com/39george/authpher/adapters/helpers"
	"github.com/39george/authpher/adapters/helpers/testbackend"
	"github.com/39george/authpher/sessions/ginsessions"
)

func runServer(permission string) (net.Addr, error) {
	// Prepare
	r := gin.Default()
	redisClient := helpers.GetRedisConnectionPool()
	err := redisClient.Ping(context.Background()).Err()
	if err != nil {
		return nil, err
	}
	sessionManager := scs.New()
	sessionManager.Store = scsRedisStore.New(redisClient)
	sessionManager.Lifetime = 24 * time.Hour
	sessionAdapter := ginAdapter.New(sessionManager)

	// Middleware
	r.Use(sessionAdapter.LoadAndSave)
	r.Use(authgin.Auth(
		testbackend.TestBackend{},
		&ginsessions.GinSessions{Store: sessionAdapter}),
	)

	// Open routes
	r.POST("/login", func(c *gin.Context) {
		credentials := new(testbackend.TestCredentials)
		err := c.ShouldBindBodyWithJSON(credentials)
		if err != nil {
			c.AbortWithStatus(http.StatusBadRequest)
			return
		}
		aS, _ := c.Get(authpher.AuthContextString)
		authSession := aS.(*authpher.AuthSession[string, testbackend.TestCredentials])
		user, err := authSession.Authenticate(c, *credentials)
		if err != nil {
			c.AbortWithError(http.StatusUnauthorized, err)
			return
		}
		if user != nil {
			u := user.(*testbackend.TestUser)
			err = authSession.Login(c, u)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
			} else {
				c.Status(http.StatusOK)

			}
		} else {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	})

	// Protected routes
	protected := r.Group("/protected")
	protected.Use(authgin.PermissionRequired[string, testbackend.TestCredentials](permission))
	protected.GET("/testpath", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	listener, err := net.Listen(
		"tcp",
		"localhost:",
	)
	if err != nil {
		return nil, err
	}
	go r.RunListener(listener)
	return listener.Addr(), nil
}

func TestUnauthenticatedAccessRestricted(t *testing.T) {
	assert := assert.New(t)
	addr, err := runServer("userpermission")
	assert.NoError(err)

	webClient := &http.Client{Jar: helpers.NewJar()}

	req := fmt.Sprintf("http://%s/protected/testpath", addr.String())
	resp, err := webClient.Get(req)
	assert.NoError(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusUnauthorized, resp.StatusCode)

}

func TestAuthorizedAccessAllowed(t *testing.T) {
	assert := assert.New(t)
	addr, err := runServer("userpermission")
	assert.NoError(err)

	webClient := &http.Client{Jar: helpers.NewJar()}

	req := fmt.Sprintf("http://%s/login", addr.String())
	creds := testbackend.TestCredentials{
		Username: "testuser",
		Password: "testpassword",
	}
	body, err := json.Marshal(&creds)
	assert.NoError(err)
	resp, err := webClient.Post(req, "application/json", bytes.NewReader(body))
	assert.NoError(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	req = fmt.Sprintf("http://%s/protected/testpath", addr.String())
	resp, err = webClient.Get(req)
	assert.NoError(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusOK, resp.StatusCode)
}

func TestUnauthorizedAccessForbidden(t *testing.T) {
	assert := assert.New(t)
	addr, err := runServer("adminpermission")
	assert.NoError(err)

	webClient := &http.Client{Jar: helpers.NewJar()}

	req := fmt.Sprintf("http://%s/login", addr.String())
	creds := testbackend.TestCredentials{
		Username: "testuser",
		Password: "testpassword",
	}
	body, err := json.Marshal(&creds)
	assert.NoError(err)
	resp, err := webClient.Post(req, "application/json", bytes.NewReader(body))
	assert.NoError(err)
	assert.Equal(http.StatusOK, resp.StatusCode)
	req = fmt.Sprintf("http://%s/protected/testpath", addr.String())
	resp, err = webClient.Get(req)
	assert.NoError(err)
	defer resp.Body.Close()
	assert.Equal(http.StatusForbidden, resp.StatusCode)
}

// Helpers

func AbortOnInternalError(c *gin.Context, err error) bool {
	if err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return true
	}
	return false
}
