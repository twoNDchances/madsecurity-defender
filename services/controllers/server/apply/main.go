package apply

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

func Apply(context *gin.Context, security *globals.Security, storage *globals.Storage) {
	var responseApiForm globals.Application
	if err := context.ShouldBindBodyWithJSON(&responseApiForm); err != nil {
		abort.BadRequest(context, security, err.Error())
		return
	}
	var wg sync.WaitGroup
	wg.Add(5)
	go inmemory.Add(&wg, &globals.Groups, responseApiForm.Groups)
	go inmemory.Add(&wg, &globals.Rules, responseApiForm.Rules)
	go inmemory.Add(&wg, &globals.Targets, responseApiForm.Targets)
	go inmemory.Add(&wg, &globals.Wordlists, responseApiForm.Wordlists)
	go inmemory.Add(&wg, &globals.Words, responseApiForm.Words)
	data := make(gin.H, 0)
	var (
		groups    int64
		rules     int64
		targets   int64
		wordlists int64
		words     int64
		errs      globals.ListError
	)
	if storage.Type == "redis" {
		wg.Add(5)
		go inredis.Add(&wg, responseApiForm.Groups, "groups", &groups, &errs)
		go inredis.Add(&wg, responseApiForm.Rules, "rules", &rules, &errs)
		go inredis.Add(&wg, responseApiForm.Targets, "targets", &targets, &errs)
		go inredis.Add(&wg, responseApiForm.Wordlists, "wordlists", &wordlists, &errs)
		go inredis.Add(&wg, responseApiForm.Words, "words", &words, &errs)
	}
	wg.Wait()
	responseApiForm = globals.Application{}
	switch storage.Type {
	case "memory":
		if len(errs) > 0 {
			abort.InternalServerError(context, security, errors.Join(errs...).Error())
			return
		}
		data = gin.H{
			"group":    len(globals.Groups),
			"rule":     len(globals.Rules),
			"target":   len(globals.Targets),
			"wordlist": len(globals.Wordlists),
			"word":     len(globals.Words),
		}
	case "redis":
		data = gin.H{
			"group":    groups,
			"rule":     rules,
			"target":   targets,
			"wordlist": wordlists,
			"word":     words,
		}
	}
	tmpGroups := make([]globals.Group, 0)
	for _, group := range globals.Groups {
		tmpGroups = append(tmpGroups, group)
	}
	globals.ListGroups = append(globals.ListGroups, tmpGroups...)
	globals.SortGroup(globals.ListGroups)
	complete.OK(context, "applied", data)
}
