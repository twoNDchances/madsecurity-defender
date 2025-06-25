package apply

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/abort"
	"madsecurity-defender/services/controllers/proxy/complete"
	"sync"

	"github.com/gin-gonic/gin"
)

func Apply(context *gin.Context) {
	var responseApiForm globals.Application
	if err := context.ShouldBindBodyWithJSON(&responseApiForm); err != nil {
		abort.BadRequest(context, err.Error())
		return
	}
	var wg sync.WaitGroup
	wg.Add(5)
	go add(&wg, &globals.Groups, responseApiForm.Groups, &globals.TmpGroups)
	go add(&wg, &globals.Rules, responseApiForm.Rules, &globals.TmpRules)
	go add(&wg, &globals.Targets, responseApiForm.Targets, &globals.TmpTargets)
	go add(&wg, &globals.Wordlists, responseApiForm.Wordlists, &globals.TmpWordlists)
	go add(&wg, &globals.Words, responseApiForm.Words, &globals.TmpWords)
	complete.OK(
		context,
		"applied",
		gin.H{
			"group": len(responseApiForm.Groups),
			"rule": len(responseApiForm.Rules),
			"target": len(responseApiForm.Targets),
			"wordlist": len(responseApiForm.Wordlists),
			"word": len(responseApiForm.Words),
		},
	)
}

func add[T globals.Identifiable](wg *sync.WaitGroup, models *[]T, preModels []T, tmpModels *[]T) {
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
