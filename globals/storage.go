package globals

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"madsecurity-defender/utils"
	"slices"
	"sync"

	"github.com/redis/go-redis/v9"
)

var (
	RedisContext = context.Background()
	RedisClient  *redis.Client
)

type RedisStorage struct {
	Host     string
	Port     int
	Password string
	Database int
}

func (r *RedisStorage) validate() ListError {
	if errors := Validate(
		r.validatePort(),
		r.validateDatabase(),
		r.validateConnection(),
		r.assignValue(),
	); len(errors) > 0 {
		return errors
	}
	return nil
}

func (r *RedisStorage) validatePort() error {
	if r.Port <= 0 || r.Port >= 100000 {
		return utils.NewServerError("Storage.Redis.Port", "Must in range 1 -> 99999")
	}
	return nil
}

func (r *RedisStorage) validateDatabase() error {
	if r.Database < 0 || r.Database > 2147483647 {
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


func (r *RedisStorage) assignValue() error {
	var (
		wg sync.WaitGroup
		errs ListError
	)
	wg.Add(6)
	go r.getAndSetValue(&wg, "groups", &errs)
	go r.getAndSetValue(&wg, "rules", &errs)
	go r.getAndSetValue(&wg, "targets", &errs)
	go r.getAndSetValue(&wg, "wordlists", &errs)
	go r.getAndSetValue(&wg, "words", &errs)
	go r.getAndSetValue(&wg, "decisions", &errs)
	wg.Wait()
	if len(errs) > 0 {
		return utils.NewServerError("Storage.Redis", errors.Join(errs...).Error())
	}
	SortGroup(ListGroups)
	return nil
}

func (r *RedisStorage) getAndSetValue(wg *sync.WaitGroup, structName string, errors *ListError) {
	defer wg.Done()
	hashKey := fmt.Sprintf("defender_%s", structName)
	res, err := RedisClient.HGetAll(RedisContext, hashKey).Result()
	if err != nil {
		*errors = append(*errors, err)
		return
	}
	for _, r := range res {
		if structName == "groups" {
			var group Group
			if err := json.Unmarshal([]byte(r), &group); err != nil {
				*errors = append(*errors, err)
				continue
			}
			Groups[group.ID] = group
			ListGroups = append(ListGroups, group)
		} else if structName == "rules" {
			var rule Rule
			if err := json.Unmarshal([]byte(r), &rule); err != nil {
				*errors = append(*errors, err)
				continue
			}
			Rules[rule.ID] = rule
		} else if structName == "targets" {
			var target Target
			if err := json.Unmarshal([]byte(r), &target); err != nil {
				*errors = append(*errors, err)
				continue
			}
			Targets[target.ID] = target
		} else if structName == "wordlists" {
			var wordlist Wordlist
			if err := json.Unmarshal([]byte(r), &wordlist); err != nil {
				*errors = append(*errors, err)
				continue
			}
			Wordlists[wordlist.ID] = wordlist
		} else if structName == "words" {
			var word Word
			if err := json.Unmarshal([]byte(r), &word); err != nil {
				*errors = append(*errors, err)
				continue
			}
			Words[word.ID] = word
		} else if structName == "decisions" {
			var decision Decision
			if err := json.Unmarshal([]byte(r), &decision); err != nil {
				*errors = append(*errors, err)
				continue
			}
			Decisions[decision.ID] = decision
		}
	}
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
