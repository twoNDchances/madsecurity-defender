package inredis

import (
	"encoding/json"
	"fmt"
	"madsecurity-defender/globals"
	"sync"
)

func Add[T globals.Identifiable](wg *sync.WaitGroup, preModels []T, structName string, result *int64, errors *globals.ListError) {
	defer wg.Done()
	if len(preModels) == 0 {
		return
	}
	data := make(map[string]interface{})
	hashKey := fmt.Sprintf("defender_%s", structName)
	for _, pre := range preModels {
		id := fmt.Sprint(pre.GetID())
		jsonData, err := json.Marshal(pre)
		if err != nil {
			*errors = append(*errors, err)
			continue
		}
		data[id] = jsonData
	}
	if len(data) == 0 {
		return
	}
	res, err := globals.RedisClient.HSet(globals.RedisContext, hashKey, data).Result()
	if err != nil {
		*errors = append(*errors, err)
	}
	*result = res
}

func Remove(wg *sync.WaitGroup, ids *globals.ListUint, structName string, result *int64, errors *globals.ListError) {
	defer wg.Done()
	if len(*ids) == 0 {
		return
	}
	hashKey := fmt.Sprintf("defender_%s", structName)
	strIds := make(globals.ListString, 0)

	for _, id := range *ids {
		strIds = append(strIds, fmt.Sprint(id))
	}
	res, err := globals.RedisClient.HDel(globals.RedisContext, hashKey, strIds...).Result()
	if err != nil {
		*errors = append(*errors, err)
	}
	*result = res
}
