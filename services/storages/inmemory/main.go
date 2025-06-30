package inmemory

import (
	"madsecurity-defender/globals"
	"sync"
)

func Add[T globals.Identifiable](wg *sync.WaitGroup, models *map[uint]T, preModels []T) {
	defer wg.Done()
	if len(preModels) == 0 {
		return
	}
	var mutex sync.Mutex
	mutex.Lock()
	for _, pre := range preModels {
		if _, ok := (*models)[pre.GetID()]; ok {
			continue
		}
		(*models)[pre.GetID()] = pre
	}
	mutex.Unlock()
}


func Remove[T globals.Identifiable](wg *sync.WaitGroup, models *map[uint]T, preModels *globals.ListUint) {
	defer wg.Done()
	if len(*preModels) == 0 {
		return
	}
	var mutex sync.Mutex
	mutex.Lock()
	for _, pre := range *preModels {
		delete(*models, pre)
	}
	mutex.Unlock()
}

