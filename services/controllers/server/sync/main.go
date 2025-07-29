package sync

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/server/abort"
	"madsecurity-defender/services/controllers/server/complete"
	"math"
	"strconv"
	"sync"

	"github.com/gin-gonic/gin"
)

func paginate[T any](data []T, page, pageSize int) ([]T, int) {
	totalItems := len(data)
	totalPages := int(math.Ceil(float64(totalItems) / float64(pageSize)))
	start := (page - 1) * pageSize
	if start >= totalItems {
		return []T{}, totalPages
	}
	end := min(start + pageSize, totalItems)
	return data[start:end], totalPages
}

func Sync(context *gin.Context) {
	page, err := strconv.Atoi(context.DefaultQuery("page", "1"))
	if err != nil {
		abort.InternalServerError(context, err.Error())
		return
	}
	pageSize, err := strconv.Atoi(context.DefaultQuery("pageSize", "10000"))
	if err != nil {
		abort.InternalServerError(context, err.Error())
		return
	}
	var (
		rules     = make([]globals.Rule, 0)
		targets   = make([]globals.Target, 0)
		wordlists = make([]globals.Wordlist, 0)
		words     = make([]globals.Word, 0)
		decisions = make([]globals.Decision, 0)
	)
	var wg sync.WaitGroup
	wg.Add(5)
	go func() {
		defer wg.Done()
		for _, rule := range globals.Rules {
			rules = append(rules, rule)
		}
	}()
	go func() {
		defer wg.Done()
		for _, target := range globals.Targets {
			targets = append(targets, target)
		}
	}()
	go func() {
		defer wg.Done()
		for _, wordlist := range globals.Wordlists {
			wordlists = append(wordlists, wordlist)
		}
	}()
	go func() {
		defer wg.Done()
		for _, word := range globals.Words {
			words = append(words, word)
		}
	}()
	go func() {
		defer wg.Done()
		for _, decision := range globals.Decisions {
			decisions = append(decisions, decision)
		}
	}()
	wg.Wait()
	pagedGroups, groupsPages := paginate(globals.ListGroups, page, pageSize)
	pagedRules, rulesPages := paginate(rules, page, pageSize)
	pagedTargets, targetsPages := paginate(targets, page, pageSize)
	pagedWordlists, wordlistsPages := paginate(wordlists, page, pageSize)
	pagedWords, wordsPages := paginate(words, page, pageSize)
	pagedDecisions, decisionsPages := paginate(decisions, page, pageSize)
	complete.OK(context, "synced", gin.H{
		"resources": gin.H{
			"groups":    pagedGroups,
			"rules":     pagedRules,
			"targets":   pagedTargets,
			"wordlists": pagedWordlists,
			"words":     pagedWords,
			"decisions": pagedDecisions,
		},
		"counters": gin.H{
			"groups":    len(globals.ListGroups),
			"rules":     len(rules),
			"targets":   len(targets),
			"wordlists": len(wordlists),
			"words":     len(words),
			"decisions": len(decisions),
		},
		"pages": gin.H{
			"currentPage": page,
			"pageSize":    pageSize,
			"totalPages": gin.H{
				"groups":    groupsPages,
				"rules":     rulesPages,
				"targets":   targetsPages,
				"wordlists": wordlistsPages,
				"words":     wordsPages,
				"decisions": decisionsPages,
			},
			"remainingPages": gin.H{
				"groups":    max(0, groupsPages-page),
				"rules":     max(0, rulesPages-page),
				"targets":   max(0, targetsPages-page),
				"wordlists": max(0, wordlistsPages-page),
				"words":     max(0, wordsPages-page),
				"decisions": max(0, decisionsPages-page),
			},
		},
	})
}
