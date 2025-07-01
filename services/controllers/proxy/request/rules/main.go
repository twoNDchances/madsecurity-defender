package rules

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
	"slices"
	"strconv"

	"github.com/gin-gonic/gin"
)

func Similar(context *gin.Context, targets globals.ListString, rule *globals.Rule) bool {
	var result bool
	if rule.WordlistID == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Wordlist ID for Similar comparator"))
		return result
	}
	words := make(globals.ListString, 0)
	for _, word := range globals.Words {
		if word.WordlistID == *rule.WordlistID {
			words = append(words, word.Content)
		}
	}
	for _, target := range targets {
		if rule.Inverse {
			result = !slices.Contains(words, target)
		} else {
			result = slices.Contains(words, target)
		}
	}
	return result
}

func Contains(context *gin.Context, targets globals.ListString, rule *globals.Rule) bool {
	if rule.Value != nil {
		if rule.Inverse {
			return !slices.Contains(targets, *rule.Value)
		} else {
			return slices.Contains(targets, *rule.Value)
		}
	} else {}
	return false
}

func Equal(context *gin.Context, target float64, rule *globals.Rule) bool {
	if rule.Value != nil {
		value, err := strconv.ParseFloat(*rule.Value, 64)
		if err == nil {} else {
			if rule.Inverse {
				return target != value
			} else {
				return target == value
			}
		}
	} else {}
	return false
}

func GreaterThan(context *gin.Context, target float64, rule *globals.Rule) bool {
	if rule.Value != nil {
		value, err := strconv.ParseFloat(*rule.Value, 64)
		if err == nil {} else {
			if rule.Inverse {
				return target < value
			} else {
				return target > value
			}
		}
	} else {}
	return false
}

func LessThan(context *gin.Context, target float64, rule *globals.Rule) bool {
	if rule.Value != nil {
		value, err := strconv.ParseFloat(*rule.Value, 64)
		if err == nil {} else {
			if rule.Inverse {
				return target > value
			} else {
				return target < value
			}
		}
	} else {}
	return false
}

func GreaterThanOrEqual(context *gin.Context, target float64, rule *globals.Rule) bool {
	if rule.Value != nil {
		value, err := strconv.ParseFloat(*rule.Value, 64)
		if err == nil {} else {
			if rule.Inverse {
				return target <= value
			} else {
				return target >= value
			}
		}
	} else {}
	return false
}
