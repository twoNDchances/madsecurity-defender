package globals

import (
	"context"
	"fmt"
	"madsecurity-defender/utils"
	"net"
	"slices"

	"github.com/redis/go-redis/v9"
)

var (
	RedisContext = context.Background()
	RedisClient  *redis.Client
)

type RedisStorage struct {
	Host     string
	Port     uint32
	Password string
	Database uint32
}

func (r *RedisStorage) validate() ListError {
	if errors := Validate(
		r.validateHost(),
		r.validatePort(),
		r.validateDatabase(),
		r.validateConnection(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (r *RedisStorage) validateHost() error {
	if r.Host == "" {
		return nil
	}
	if net.ParseIP(r.Host) == nil {
		return utils.NewServerError("Storage.Redis.Host", "Invalid IP")
	}
	return nil
}

func (r *RedisStorage) validatePort() error {
	if r.Port <= 0 || r.Port >= ^uint32(0) {
		return utils.NewServerError("Storage.Redis.Port", "Must in range 1 -> 4294967295")
	}
	return nil
}

func (r *RedisStorage) validateDatabase() error {
	if r.Database > 2147483647 {
		return utils.NewServerError("Storage.Redis.Database", "Out of range")
	}
	return nil
}

func (r *RedisStorage) validateConnection() error {
	RedisClient = redis.NewClient(&redis.Options{
		Addr:     fmt.Sprintf("%s:%d", r.Host, r.Port),
		Password: r.Password,
		DB:       int(r.Database),
	})
	if err := RedisClient.Ping(RedisContext).Err(); err != nil {
		return utils.NewServerError("Storage.Redis", err.Error())
	}
	return nil
}

var storageTypes = ListString{
	"memory",
	"redis",
}

type Storage struct {
	Type          string
	RedisStorage  RedisStorage
}

func (s *Storage) Validate() ListError {
	errors := make(ListError, 0)
	if err := s.validateType(); err != nil {
		errors = append(errors, err)
	}
	if errs := s.validateRedisStorage(); errs != nil {
		errors = append(errors, errs...)
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}

func (s *Storage) validateType() error {
	if !slices.Contains(storageTypes, s.Type) {
		return utils.NewServerError("Storage.Type", "Must be 'memory' or 'redis'")
	}
	return nil
}

func (s *Storage) validateRedisStorage() ListError {
	errors := make(ListError, 0)
	if s.Type == "redis" {
		if errs := s.RedisStorage.validate(); errs != nil {
			errors = append(errors, errs...)
		}
	}
	if len(errors) > 0 {
		return errors
	}
	return nil
}
