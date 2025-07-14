package comparators

import "madsecurity-defender/globals"

func Compare(target any, rule *globals.Rule) bool {
	var result bool
	switch t := target.(type) {
	case globals.ListString:
		switch rule.Comparator {
		case "@similar":
			result = Similar(t, rule)
		case "@contains":
			result = Contains(t, rule)
		case "@match":
			result = Match(t, rule)
		case "@search":
			result = Search(t, rule)
		}
	case float64:
		switch rule.Comparator {
		case "@equal":
			result = Equal(t, rule)
		case "@greaterThan":
			result = GreaterThan(t, rule)
		case "@greaterThanOrEqual":
			result = GreaterThanOrEqual(t, rule)
		case "@lessThan":
			result = LessThan(t, rule)
		case "@lessThanOrEqual":
			result = LessThanOrEqual(t, rule)
		case "@inRange":
			result = InRange(t, rule)
		}
	case string:
		switch rule.Comparator {
		case "@mirror":
			result = Mirror(t, rule)
		case "@startsWith":
			result = StartsWith(t, rule)
		case "@endsWith":
			result = EndsWith(t, rule)
		case "@check":
			result = Check(t, rule)
		case "@regex":
			result = Regex(t, rule)
		case "@checkRegex":
			result = CheckRegex(t, rule)
		}
	}
	return result
}
