package redis

import (
	"context"
	"errors"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	ErrSet       = errors.New("unable to set redis value")
	ErrGet       = errors.New("unable to get redis value")
	ErrDiffValue = errors.New("values are different")
)

// New generates a new redis connection.
// Insert password as "" if you'd like no password.
// Insert 0 as db if you'd like default redis db.
func New(address, password string, db int) *redis.Client {
	rdb := redis.NewClient(&redis.Options{
		Addr:     address,
		Password: password,
		DB:       db,
		Protocol: 2,
	})
	return rdb
}

// Ping tests the redis connection by checking a temp value.
func Ping(rdb *redis.Client) error {
	ctx := context.Background()

	err := rdb.Set(ctx, "foo", "bar", 5*time.Second).Err()
	if err != nil {
		return ErrSet
	}
	val, err := rdb.Get(ctx, "foo").Result()
	if err != nil {
		return ErrGet
	}
	if val != "bar" {
		return ErrDiffValue
	}
	return nil
}
