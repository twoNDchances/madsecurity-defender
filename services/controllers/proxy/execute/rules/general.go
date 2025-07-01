package rules

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/utils"
	"regexp"
	"slices"
	"strconv"
	"strings"

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
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Contains comparator"))
		return result
	}
	if rule.Inverse {
		result = !slices.Contains(targets, *rule.Value)
	} else {
		result = slices.Contains(targets, *rule.Value)
	}
	return result
}

func Equal(context *gin.Context, target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Equal comparator"))
		return result
	}
	value, err := strconv.ParseFloat(*rule.Value, 64)
	if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
		return result
	}
	if rule.Inverse {
		result = target != value
	} else {
		result = target == value
	}
	return result
}

func GreaterThan(context *gin.Context, target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Greater Than comparator"))
		return result
	}
	value, err := strconv.ParseFloat(*rule.Value, 64)
	if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
		return result
	}
	if rule.Inverse {
		result = target < value
	} else {
		result = target > value
	}
	return result
}

func LessThan(context *gin.Context, target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Less Than comparator"))
		return result
	}
	value, err := strconv.ParseFloat(*rule.Value, 64)
	if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
		return result
	}
	if rule.Inverse {
		result = target > value
	} else {
		result = target < value
	}
	return result
}

func GreaterThanOrEqual(context *gin.Context, target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Greater Than Or Equal comparator"))
		return result
	}
	value, err := strconv.ParseFloat(*rule.Value, 64)
	if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
		return result
	}
	if rule.Inverse {
		result = target <= value
	} else {
		result = target >= value
	}
	return result
}

func LessThanOrEqual(context *gin.Context, target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Less Than Or Equal comparator"))
		return result
	}
	value, err := strconv.ParseFloat(*rule.Value, 64)
	if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
		return result
	}
	if rule.Inverse {
		result = target >= value
	} else {
		result = target <= value
	}
	return result
}

func InRange(context *gin.Context, target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for In Range comparator"))
		return result
	}
	values := strings.Split(*rule.Value, ",")
	if len(values) != 2 {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "unsatisfactory value for In Range comparator"))
		return result
	}
	value1, err := strconv.ParseFloat(values[0], 64)
	if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
		return result
	}
	value2, err := strconv.ParseFloat(values[1], 64)
	if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
		return result
	}
	if rule.Inverse {
		result = !(target >= value1 && target <= value2)
	} else {
		result = (target >= value1 && target <= value2)
	}
	return result
}

func Mirror(context *gin.Context, target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Mirror comparator"))
		return result
	}
	if rule.Inverse {
		result = target != *rule.Value
	} else {
		result = target == *rule.Value
	}
	return result
}

func StartsWith(context *gin.Context, target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Strats With comparator"))
		return result
	}
	if rule.Inverse {
		result = !strings.HasPrefix(target, *rule.Value)
	} else {
		result = strings.HasPrefix(target, *rule.Value)
	}
	return result
}

func EndsWith(context *gin.Context, target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Ends With comparator"))
		return result
	}
	if rule.Inverse {
		result = !strings.HasSuffix(target, *rule.Value)
	} else {
		result = strings.HasSuffix(target, *rule.Value)
	}
	return result
}

func Check(context *gin.Context, target string, rule *globals.Rule) bool {
	var result bool
	if rule.WordlistID == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Wordlist ID for Check comparator"))
		return result
	}
	words := make(globals.ListString, 0)
	for _, word := range globals.Words {
		if word.WordlistID == *rule.WordlistID {
			words = append(words, word.Content)
		}
	}
	if rule.Inverse {
		result = !slices.Contains(words, target)
	} else {
		result = slices.Contains(words, target)
	}
	return result
}

func Regex(context *gin.Context, target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Value for Regex comparator"))
		return result
	}
	matched, err := regexp.MatchString(*rule.Value, target)
    if err != nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
        return result
    }
	if rule.Inverse {
		result = !matched
	} else {
		result = matched
	}
	return result
}

func CheckRegex(context *gin.Context, target string, rule *globals.Rule) bool {
	var result bool
	if rule.WordlistID == nil {
		context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), "missing Wordlist ID for Check Regex comparator"))
		return result
	}
	words := make(globals.ListString, 0)
	for _, word := range globals.Words {
		if word.WordlistID == *rule.WordlistID {
			words = append(words, word.Content)
		}
	}
	for _, word := range words {
		matched, err := regexp.MatchString(word, target)
		if err != nil {
			context.Error(utils.NewProxyError(fmt.Sprintf("Rule.%d", rule.ID), err.Error()))
			break
		}
		if rule.Inverse {
			result = !matched
		} else {
			result = matched
		}
	}
	return result
}
