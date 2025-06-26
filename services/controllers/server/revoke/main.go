package revoke

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"
	"madsecurity-defender/services/controllers/server/complete"
	"madsecurity-defender/services/storages/inmemory"
	"sync"

	"github.com/gin-gonic/gin"
)

func Revoke(context *gin.Context, storage *globals.Storage) {
	var responseApiForm globals.Revocation
	if err := context.ShouldBindBodyWithJSON(&responseApiForm); err != nil {
		abort.BadRequest(context, err.Error())
		return
	}
	var wg sync.WaitGroup
	if storage.Type == "memory" {
		wg.Add(5)
		go inmemory.Remove(&wg, &globals.Groups, &responseApiForm.Groups)
		go inmemory.Remove(&wg, &globals.Rules, &responseApiForm.Rules)
		go inmemory.Remove(&wg, &globals.Targets, &responseApiForm.Targets)
		go inmemory.Remove(&wg, &globals.Wordlists, &responseApiForm.Wordlists)
		go inmemory.Remove(&wg, &globals.Words, &responseApiForm.Words)
		wg.Wait()
		complete.OK(
			context,
			"revoked",
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
			"revoked",
			gin.H{
				
			},
		)
	}
}
