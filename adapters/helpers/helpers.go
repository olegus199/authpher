package helpers

import (
	"os"

	"github.com/redis/go-redis/v9"
)

func GetRedisConnectionPool() *redis.Client {
	opts := &redis.Options{
		Addr:     getEnv("REDIS_ADDR"),
		Password: getEnv("REDIS_PASS"),
		DB:       0,
	}
	return redis.NewClient(opts)
}

func getEnv(key string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	} else {
		panic("Not found key in the environment: " + key)
	}
}
