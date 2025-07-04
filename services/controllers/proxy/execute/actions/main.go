package actions

import "madsecurity-defender/globals"

func Perform(
	proxy *globals.Proxy,
	target *globals.Target,
	targetValue any,
	rule *globals.Rule,
	defaultScore *int,
	score *int,
	level *int,
) (bool, bool) {
	var forceReturn, result bool
	switch *rule.Action {
	case "allow":
		forceReturn, result = Allow()
	case "deny":
		forceReturn, result = Deny()
	case "inspect":
		forceReturn, result = Inspect(proxy, rule, defaultScore)
	case "request":
		forceReturn, result = Request(proxy, targetValue, rule)
	case "setScore":
		forceReturn, result = SetScore(proxy, rule, score)
	case "setLevel":
		forceReturn, result = SetLevel(proxy, rule, level)
	case "report":
		forceReturn, result = Report(proxy, targetValue, rule)
	}
	return forceReturn, result
}
