package sync

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/complete"

	"github.com/gin-gonic/gin"
)

func Sync(context *gin.Context, security *globals.Security) {
	var (
		rules   = make([]globals.Rule, 0)
		targets = make([]globals.Target, 0)
		wordlists = make([]globals.Wordlist, 0)
		words   = make([]globals.Word, 0)
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
	complete.OK(context, "synced", gin.H{
		"groups":    globals.ListGroups,
		"rules":     rules,
		"targets":   targets,
		"wordlists": wordlists,
		"words":     words,
		"counter": gin.H{
			"groups":    len(globals.ListGroups),
			"rules":     len(rules),
			"targets":   len(targets),
			"wordlists": len(wordlists),
			"words":     len(words),
		},
	})
}
