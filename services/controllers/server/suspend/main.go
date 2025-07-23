package suspend

import (
	"errors"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"
	"madsecurity-defender/services/controllers/server/complete"
	"madsecurity-defender/services/storages/inmemory"
	"madsecurity-defender/services/storages/inredis"
	"sync"

	"github.com/gin-gonic/gin"
)

func Suspend(context *gin.Context) {
	var responseApiForm globals.Suspension
	if err := context.ShouldBindBodyWithJSON(&responseApiForm); err != nil {
		abort.BadRequest(context, err.Error())
		return
	}
	var wg sync.WaitGroup
	wg.Add(3)
	go inmemory.Remove(&wg, &globals.Decisions, &responseApiForm.Decisions)
	go inmemory.Remove(&wg, &globals.Wordlists, &responseApiForm.Wordlists)
	go inmemory.Remove(&wg, &globals.Words, &responseApiForm.Words)
	data := make(gin.H, 0)
	var (
		decisions int64
		wordlists int64
		words     int64
		errs      globals.ListError
	)
	if globals.StorageConfigs.Type == "redis" {
		wg.Add(3)
		go inredis.Remove(&wg, &responseApiForm.Decisions, "decisions", &decisions, &errs)
		go inredis.Remove(&wg, &responseApiForm.Wordlists, "wordlists", &wordlists, &errs)
		go inredis.Remove(&wg, &responseApiForm.Words, "words", &words, &errs)
	}
	wg.Wait()
	responseApiForm = globals.Suspension{}
	switch globals.StorageConfigs.Type {
	case "memory":
		data = gin.H{
			"decision": len(globals.Decisions),
			"wordlist": len(globals.Wordlists),
			"word":     len(globals.Words),
		}
	case "redis":
		if len(errs) > 0 {
			abort.InternalServerError(context, errors.Join(errs...).Error())
			return
		}
		data = gin.H{
			"decision": decisions,
			"wordlist": wordlists,
			"word":     words,
		}
	}
	complete.OK(context, "suspended", data)
}
