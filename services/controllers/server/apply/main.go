package apply

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"
	"madsecurity-defender/services/controllers/server/complete"
	"madsecurity-defender/services/storages/inmemory"
	"sync"

	"github.com/gin-gonic/gin"
)

func Apply(context *gin.Context, storage *globals.Storage) {
	var responseApiForm globals.Application
	if err := context.ShouldBindBodyWithJSON(&responseApiForm); err != nil {
		abort.BadRequest(context, err.Error())
		return
	}
	var wg sync.WaitGroup
	if storage.Type == "memory" {
		wg.Add(5)
		go inmemory.Add(&wg, &globals.Groups, responseApiForm.Groups, &globals.TmpGroups)
		go inmemory.Add(&wg, &globals.Rules, responseApiForm.Rules, &globals.TmpRules)
		go inmemory.Add(&wg, &globals.Targets, responseApiForm.Targets, &globals.TmpTargets)
		go inmemory.Add(&wg, &globals.Wordlists, responseApiForm.Wordlists, &globals.TmpWordlists)
		go inmemory.Add(&wg, &globals.Words, responseApiForm.Words, &globals.TmpWords)
		wg.Wait()
		complete.OK(
			context,
			"applied",
			gin.H{
				"group": len(globals.Groups),
				"rule": len(globals.Rules),
				"target": len(globals.Targets),
				"wordlist": len(globals.Wordlists),
				"word": len(globals.Words),
			},
		)
	}
	if storage.Type == "redis" {
		complete.OK(
			context,
			"applied",
			gin.H{

			},
		)
	}
}
