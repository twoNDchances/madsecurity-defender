package sync

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/complete"

	"github.com/gin-gonic/gin"
)

func Sync(context *gin.Context) {
	var (
		rules     = make([]globals.Rule, 0)
		targets   = make([]globals.Target, 0)
		wordlists = make([]globals.Wordlist, 0)
		words     = make([]globals.Word, 0)
		decisions = make([]globals.Decision, 0)
	)
	for _, rule := range globals.Rules {
		rules = append(rules, rule)
	}
	for _, target := range globals.Targets {
		targets = append(targets, target)
	}
	for _, wordlist := range globals.Wordlists {
		wordlists = append(wordlists, wordlist)
	}
	for _, word := range globals.Words {
		words = append(words, word)
	}
	for _, decision := range globals.Decisions {
		decisions = append(decisions, decision)
	}
	complete.OK(context, "synced", gin.H{
		"decisions": decisions,
		"groups":    globals.ListGroups,
		"rules":     rules,
		"targets":   targets,
		"wordlists": wordlists,
		"words":     words,
		"counter": gin.H{
			"decisions": len(decisions),
			"groups":    len(globals.ListGroups),
			"rules":     len(rules),
			"targets":   len(targets),
			"wordlists": len(wordlists),
			"words":     len(words),
		},
	})
}
