package rules

import (
	"log"
	"madsecurity-defender/globals"

	"github.com/gin-gonic/gin"
)

func CheckRule(context *gin.Context, target any, rule *globals.Rule) bool {
	var result bool
	switch t := target.(type) {
	case globals.ListString:
		switch rule.Comparator {
		case "@similar":
			result = Similar(context, t, rule)
			log.Println(result)
		case "@contains":
			result = Contains(context, t, rule)
		}
	case float64:
		switch rule.Comparator {
		case "@equal":
			result = Equal(context, t, rule)
		case "@greaterThan":
			result = GreaterThan(context, t, rule)
		case "@greaterThanOrEqual":
			result = GreaterThanOrEqual(context, t, rule)
		case "@lessThan":
			result = LessThan(context, t, rule)
		case "@lessThanOrEqual":
			result = LessThanOrEqual(context, t, rule)
		case "@inRange":
			result = InRange(context, t, rule)
		}
	case string:
		switch rule.Comparator {
		case "@mirror":
			result = Mirror(context, t, rule)
		case "@startsWith":
			result = StartsWith(context, t, rule)
		case "@endsWith":
			result = EndsWith(context, t, rule)
		case "@check":
			result = Check(context, t, rule)
		case "@regex":
			result = Regex(context, t, rule)
		case "@checkRegex":
			result = CheckRegex(context, t, rule)
		}
	}
	return result
}
