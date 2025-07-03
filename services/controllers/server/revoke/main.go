package revoke

import (
	"errors"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"
	"madsecurity-defender/services/controllers/server/complete"
	"madsecurity-defender/services/storages/inmemory"
	"madsecurity-defender/services/storages/inredis"
	"slices"
	"sync"

	"github.com/gin-gonic/gin"
)

func Revoke(context *gin.Context, security *globals.Security, storage *globals.Storage) {
	var responseApiForm globals.Revocation
	if err := context.ShouldBindBodyWithJSON(&responseApiForm); err != nil {
		abort.BadRequest(context, security, err.Error())
		return
	}
	var wg sync.WaitGroup
	wg.Add(5)
	go inmemory.Remove(&wg, &globals.Groups, &responseApiForm.Groups)
	go inmemory.Remove(&wg, &globals.Rules, &responseApiForm.Rules)
	go inmemory.Remove(&wg, &globals.Targets, &responseApiForm.Targets)
	go inmemory.Remove(&wg, &globals.Wordlists, &responseApiForm.Wordlists)
	go inmemory.Remove(&wg, &globals.Words, &responseApiForm.Words)
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
		go inredis.Remove(&wg, &responseApiForm.Groups, "groups", &groups, &errs)
		go inredis.Remove(&wg, &responseApiForm.Rules, "rules", &rules, &errs)
		go inredis.Remove(&wg, &responseApiForm.Targets, "targets", &targets, &errs)
		go inredis.Remove(&wg, &responseApiForm.Wordlists, "wordlists", &wordlists, &errs)
		go inredis.Remove(&wg, &responseApiForm.Words, "words", &words, &errs)
	}
	wg.Wait()
	tmpListGroups := make([]globals.Group, 0)
	for _, group := range globals.ListGroups {
		if !slices.Contains(responseApiForm.Groups, group.ID) {
			tmpListGroups = append(tmpListGroups, group)
		}
	}
	globals.ListGroups = tmpListGroups
	responseApiForm = globals.Revocation{}
	switch storage.Type {
	case "memory":
		data = gin.H{
			"group":    len(globals.Groups),
			"rule":     len(globals.Rules),
			"target":   len(globals.Targets),
			"wordlist": len(globals.Wordlists),
			"word":     len(globals.Words),
		}
	case "redis":
		if len(errs) > 0 {
			abort.InternalServerError(context, security, errors.Join(errs...).Error())
			return
		}
		data = gin.H{
			"group":    groups,
			"rule":     rules,
			"target":   targets,
			"wordlist": wordlists,
			"word":     words,
		}
	}
	complete.OK(context, "revoked", data)
}
