package loads

import (
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
)

func PrepareStorage() (*globals.Storage, bool) {
	status := true
	port, err := utils.ToUint(globals.StorageVars["redis.port"])
	if err != nil {
		log.Println(utils.NewServerError("Storage.Redis.Port", err.Error()))
		status = false
	}
	database, err := utils.ToUint(globals.StorageVars["redis.database"])
	if err != nil {
		log.Println(utils.NewServerError("Storage.Redis.Database", err.Error()))
		status = false
	}
	if !status {
		return nil, false
	}
	storage := globals.Storage{
		Type: globals.StorageVars["type"],
		RedisStorage: globals.RedisStorage{
			Host:     globals.StorageVars["redis.host"],
			Port:     port,
			Password: globals.StorageVars["redis.password"],
			Database: database,
		},
	}
	if errors := storage.Validate(); errors != nil {
		for _, err := range errors {
			log.Println(err)
		}
		return nil, false
	}
	return &storage, status
}
