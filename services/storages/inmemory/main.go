package inmemory

import (
	"madsecurity-defender/globals"
	"slices"
	"sync"
)

func Add[T globals.Identifiable](wg *sync.WaitGroup, models *[]T, preModels []T, tmpModels *[]T) {
	defer wg.Done()
	*tmpModels = (*tmpModels)[:0]
	exists := make(map[uint]any)
	for _, m := range *models {
		exists[m.GetID()] = nil
	}
	for _, pre := range preModels {
		if _, ok := exists[pre.GetID()]; !ok {
			*tmpModels = append(*tmpModels, pre)
			exists[pre.GetID()] = nil
		}
	}
	*models = append(*models, *tmpModels...)
}


func Remove[T globals.Identifiable](wg *sync.WaitGroup, models *[]T, preModels *globals.ListUint) {
	defer wg.Done()
	if len(*preModels) == 0 {
		return
	}
	result := (*models)[:0]
	for _, model := range *models {
		if !slices.Contains(*preModels, model.GetID()) {
			result = append(result, model)
		}
	}
	*models = result
}

