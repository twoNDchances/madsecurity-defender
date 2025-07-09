package execute

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/actions"
	"madsecurity-defender/services/controllers/proxy/execute/comparators"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/services/controllers/proxy/execute/logistics"
	"madsecurity-defender/services/controllers/proxy/execute/targets"
	"net/http"
	"slices"

	"github.com/gin-gonic/gin"
)

func Request(context *gin.Context) bool {
	context.Set("violation_level", uint(globals.ProxyConfigs.ViolationLevel))
	context.Set("current_score", 0)
	context.Set("violation_score", globals.ProxyConfigs.ViolationScore)
	groupProcessed := make(globals.ListUint, 0)
	retry := true
	for retry {
		retry = false
		for _, group := range globals.ListGroups {
			if slices.Contains(groupProcessed, group.ID) {
				continue
			}
			if group.Level > context.GetUint("violation_level") {
				continue
			}
			oldLevel := context.GetUint("violation_level")
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
				if !slices.Contains(globals.ListUint8{0, 1, 2}, rule.Phase) {
					continue
				}
				targetGetted := func() ([]globals.Target, any) {
					var (
						targetPath []globals.Target
						targetProcessed any
					)
					target, ok := globals.Targets[rule.TargetID]
					if ok {
						if target.Immutable {
							targetPath = []globals.Target{target}
							targetProcessed = targets.ProcessImmutableTarget(context, &target)
						} else {
							targetPath, targetProcessed = targets.ProcessTarget(context, target.ID)
						}
					}
					return targetPath, targetProcessed
				}
				targetPath, targetValue := targetGetted()
				if targetValue == nil {
					msg := fmt.Sprintf("Target %d: unobtainable Target", rule.TargetID)
					errors.WriteErrorTargetLog(msg)
					continue
				}
				if !comparators.Compare(targetValue, &rule) {
					continue
				}
				if rule.Action == nil {
					continue
				}
				target := globals.Targets[rule.TargetID]
				forceReturn, result := actions.Perform(context, &target, targetValue, &rule)
				if !result {
					logistic := logistics.NewLogistic(&rule)
					err := logistic.Write(context, targetValue, &targetPath, &rule)
					if err != nil {
						msg := fmt.Sprintf("Rule %d: %v", rule.ID, err)
						errors.WriteErrorLogisticLog(msg)
					}
				}
				if forceReturn {
					return result
				}
			}
			groupProcessed = append(groupProcessed, group.ID)
			if oldLevel != context.GetUint("violation_level") {
				retry = true
			}
		}
	}
	return context.GetInt("current_score") < context.GetInt("violation_score")
}

func Response(response *http.Response) bool {
	return false
}
