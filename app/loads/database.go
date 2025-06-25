package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareRedisDatabase() (*globals.RedisDatabase, bool) {
	status := true
	enable, err := utils.ToBoolean(globals.DatabaseVars["redis.enable"])
	if err != nil {
		log.Println(utils.NewProxyError("Redis.Enable", err.Error()))
		status = false
	}
	port, err := utils.ToUint(globals.DatabaseVars["redis.port"])
	if err != nil {
		log.Println(utils.NewProxyError("Redis.Port", err.Error()))
		status = false
	}
	database, err := utils.ToUint(globals.DatabaseVars["redis.database"])
	if err != nil {
		log.Println(utils.NewProxyError("Redis.Database", err.Error()))
		status = false
	}
	if !status {
		return nil, false
	}
	redisDatabase := globals.RedisDatabase{
		Enable:   enable,
		Host:     globals.DatabaseVars["redis.host"],
		Port:     port,
		Password: globals.DatabaseVars["redis.password"],
		Database: database,
	}

	if errors := redisDatabase.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &redisDatabase, true
}
