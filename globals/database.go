package globals

import (
	"context"
	"fmt"
	"madsecurity-defender/utils"
	"net"

	"github.com/redis/go-redis/v9"
)

var (
	RedisContext = context.Background()
	RedisClient  *redis.Client
)

type RedisDatabase struct {
	Enable   bool
	Host     string
	Port     uint32
	Password string
	Database uint32
}

func (r *RedisDatabase) Validate() ListError {
	errors := make(ListError, 0)
	if err := r.validateHost(); err != nil {
		errors = append(errors, err)
	}
	if err := r.validatePort(); err != nil {
		errors = append(errors, err)
	}
	if err := r.validateDatabase(); err != nil {
		errors = append(errors, err)
	}
	if err := r.validateConnection(); err != nil {
		errors = append(errors, err)
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}

func (r *RedisDatabase) validateHost() error {
	if r.Enable {
		if r.Host == "" {
			return nil
		}
		if net.ParseIP(r.Host) == nil {
			return utils.NewProxyError("Database.Redis.Host", "Invalid IP")
		}
	}
	return nil
}

func (r *RedisDatabase) validatePort() error {
	if r.Enable {
		if r.Port <= 0 || r.Port >= ^uint32(0) {
			return utils.NewProxyError("Database.Redis.Port", "Must in range 1 -> 4294967295")
		}
	}
	return nil
}

func (r *RedisDatabase) validateDatabase() error {
	if r.Enable {
		if r.Database > 2147483647 {
			return utils.NewProxyError("Database.Redis.Database", "Out of range")
		}
	}
	return nil
}

func (r *RedisDatabase) validateConnection() error {
	if r.Enable {
		RedisClient = redis.NewClient(&redis.Options{
			Addr:     fmt.Sprintf("%s:%d", r.Host, r.Port),
			Password: r.Password,
			DB:       int(r.Database),
		})
		if err := RedisClient.Ping(RedisContext).Err(); err != nil {
			return utils.NewProxyError("Database.Redis", err.Error())
		}
	}
	return nil
}
