package comparators

import "madsecurity-defender/globals"

func Compare(proxy *globals.Proxy, target any, rule *globals.Rule) bool {
	var result bool
	switch t := target.(type) {
	case globals.ListString:
		switch rule.Comparator {
		case "@similar":
			result = Similar(proxy, t, rule)
		case "@contains":
			result = Contains(proxy, t, rule)
		}
	case float64:
		switch rule.Comparator {
		case "@equal":
			result = Equal(proxy, t, rule)
		case "@greaterThan":
			result = GreaterThan(proxy, t, rule)
		case "@greaterThanOrEqual":
			result = GreaterThanOrEqual(proxy, t, rule)
		case "@lessThan":
			result = LessThan(proxy, t, rule)
		case "@lessThanOrEqual":
			result = LessThanOrEqual(proxy, t, rule)
		case "@inRange":
			result = InRange(proxy, t, rule)
		}
	case string:
		switch rule.Comparator {
		case "@mirror":
			result = Mirror(proxy, t, rule)
		case "@startsWith":
			result = StartsWith(proxy, t, rule)
		case "@endsWith":
			result = EndsWith(proxy, t, rule)
		case "@check":
			result = Check(proxy, t, rule)
		case "@regex":
			result = Regex(proxy, t, rule)
		case "@checkRegex":
			result = CheckRegex(proxy, t, rule)
		}
	}
	return result
}
