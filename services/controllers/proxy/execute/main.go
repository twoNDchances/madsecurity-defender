package execute

import (
	"errors"
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/actions"
	perform "madsecurity-defender/services/controllers/proxy/execute/rules"
	"madsecurity-defender/services/controllers/proxy/execute/targets"
	"slices"

	"github.com/gin-gonic/gin"
)

func Request(context *gin.Context, proxy *globals.Proxy) bool {
	level := globals.ViolationLevel
	score := globals.ViolationScore
	var scoreDefault int
	for _, group := range globals.ListGroups {
		if group.Level != uint(level) {
			continue
		}
		ruleGetted := func() []globals.Rule {
			rules := make([]globals.Rule, 0)
			for _, ruleId := range group.Rules {
				if rule, ok := globals.Rules[ruleId]; ok {
					rules = append(rules, rule)
				}
			}
			return rules
		}
		rules := ruleGetted()
		for _, rule := range rules {
			targetGetted := func() any {
				var targetProcessed any
				target, ok := globals.Targets[rule.TargetID]
				if ok {
					if target.Immutable {
						targetProcessed = targets.ProcessImmutableTarget(context, &target)
					} else {
						targetProcessed = targets.ProcessTarget(context, target.ID)
					}
				}
				return targetProcessed
			}
			target := targetGetted()
			if target == nil {
				msg := fmt.Sprintf("Target %d: unobtainable Target", rule.TargetID)
				context.Error(errors.New(msg))
				continue
			}
			if !slices.Contains(globals.ListUint8{0,1,2}, rule.Phase) {
				continue
			}
			if !perform.CheckRule(context, target, &rule) {
				continue
			}
			if rule.Action == nil {
				continue
			}
			targetInstace := globals.Targets[rule.TargetID]
			forceReturn, result := actions.Perform(
				context,
				proxy,
				&targetInstace,
				&rule,
				&scoreDefault,
				&score,
				&level,
			)
			if forceReturn {
				return result
			}
		}
	}
	return scoreDefault < score
}

func Response() {
	//
}
