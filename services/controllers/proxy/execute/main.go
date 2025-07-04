package execute

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/actions"
	"madsecurity-defender/services/controllers/proxy/execute/comparators"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/services/controllers/proxy/execute/logistics"
	"madsecurity-defender/services/controllers/proxy/execute/targets"
	"slices"

	"github.com/gin-gonic/gin"
)

func Request(context *gin.Context, proxy *globals.Proxy) bool {
	level := globals.ViolationLevel
	score := globals.ViolationScore
	var defaultScore int
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
			targetGetted := func() ([]globals.Target, any) {
				var (
					targetPath []globals.Target
					targetProcessed any
				)
				target, ok := globals.Targets[rule.TargetID]
				if ok {
					if target.Immutable {
						targetPath = []globals.Target{target}
						targetProcessed = targets.ProcessImmutableTarget(context, proxy, &target)
					} else {
						targetPath, targetProcessed = targets.ProcessTarget(context, proxy, target.ID)
					}
				}
				return targetPath, targetProcessed
			}
			targetPath, targetValue := targetGetted()
			if targetValue == nil {
				if proxy.HistoryErrorEnable {
					msg := fmt.Sprintf("Target %d: unobtainable Target", rule.TargetID)
					errors.WriteErrorTargetLog(proxy, msg)
				}
				continue
			}
			if !slices.Contains(globals.ListUint8{0,1,2}, rule.Phase) {
				continue
			}
			if !comparators.Compare(proxy, targetValue, &rule) {
				continue
			}
			if rule.Action == nil {
				continue
			}
			target := globals.Targets[rule.TargetID]
			forceReturn, result := actions.Perform(
				proxy,
				&target,
				targetValue,
				&rule,
				&defaultScore,
				&score,
				&level,
			)
			if !result {
				logistic := logistics.NewLogistic(
					rule.Log,
					rule.Time,
					rule.UserAgent,
					rule.ClientIP,
					rule.Method,
					rule.Path,
					rule.Output,
					rule.Target,
					rule.Rule,
				)
				err := logistic.Write(context, proxy, targetValue, &targetPath, &rule)
				if err != nil {
					msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
					errors.WriteErrorLogisticLog(proxy, msg)
				}
			}
			if forceReturn {
				return result
			}
		}
	}
	return defaultScore < score
}

func Response() {
	//
}
