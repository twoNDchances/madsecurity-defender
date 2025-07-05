package comparators

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"regexp"
	"slices"
	"strings"
)

func Similar(targets globals.ListString, rule *globals.Rule) bool {
	var result bool
	if rule.WordlistID == nil {
		msg := fmt.Sprintf("Rule %d: missing Wordlist ID for Similar comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
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
		if result {
			break
		}
	}
	return result
}

func Contains(targets globals.ListString, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Contains comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = !slices.Contains(targets, *rule.Value)
	} else {
		result = slices.Contains(targets, *rule.Value)
	}
	return result
}

func Equal(target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Equal comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	value, err := utils.ToFloat64(*rule.Value)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = target != value
	} else {
		result = target == value
	}
	return result
}

func GreaterThan(target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Greater Than comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	value, err := utils.ToFloat64(*rule.Value)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = target < value
	} else {
		result = target > value
	}
	return result
}

func LessThan(target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Less Than comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	value, err := utils.ToFloat64(*rule.Value)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = target > value
	} else {
		result = target < value
	}
	return result
}

func GreaterThanOrEqual(target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Greater Than Or Equal comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	value, err := utils.ToFloat64(*rule.Value)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = target <= value
	} else {
		result = target >= value
	}
	return result
}

func LessThanOrEqual(target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Less Than Or Equal comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	value, err := utils.ToFloat64(*rule.Value)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = target >= value
	} else {
		result = target <= value
	}
	return result
}

func InRange(target float64, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for In Range comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	values := strings.Split(*rule.Value, ",")
	if len(values) != 2 {
		msg := fmt.Sprintf("Rule %d: unsatisfactory value for In Range comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	value1, err := utils.ToFloat64(values[0])
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	value2, err := utils.ToFloat64(values[1])
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = !(target >= value1 && target <= value2)
	} else {
		result = (target >= value1 && target <= value2)
	}
	return result
}

func Mirror(target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Mirror comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = target != *rule.Value
	} else {
		result = target == *rule.Value
	}
	return result
}

func StartsWith(target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Starts With comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = !strings.HasPrefix(target, *rule.Value)
	} else {
		result = strings.HasPrefix(target, *rule.Value)
	}
	return result
}

func EndsWith(target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for End With comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = !strings.HasSuffix(target, *rule.Value)
	} else {
		result = strings.HasSuffix(target, *rule.Value)
	}
	return result
}

func Check(target string, rule *globals.Rule) bool {
	var result bool
	if rule.WordlistID == nil {
		msg := fmt.Sprintf("Rule %d: missing Wordlist ID for Check comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
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

func Regex(target string, rule *globals.Rule) bool {
	var result bool
	if rule.Value == nil {
		msg := fmt.Sprintf("Rule %d: missing Value for Regex comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	matched, err := regexp.MatchString(*rule.Value, target)
	if err != nil {
		msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
		errors.WriteErrorComparatorLog(msg)
		return result
	}
	if rule.Inverse {
		result = !matched
	} else {
		result = matched
	}
	return result
}

func CheckRegex(target string, rule *globals.Rule) bool {
	var result bool
	if rule.WordlistID == nil {
		msg := fmt.Sprintf("Rule %d: missing Wordlist ID for Check Regex comparator", rule.ID)
		errors.WriteErrorComparatorLog(msg)
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
			msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
			errors.WriteErrorComparatorLog(msg)
			break
		}
		if rule.Inverse {
			result = !matched
		} else {
			result = matched
		}
		if result {
			break
		}
	}
	return result
}
