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

type actionCallback struct {
	targetPath  []globals.Target
	targetValue any
	rule        *globals.Rule
}

func Execute(context any, contextGin *gin.Context) bool {
	groupProcessed := make(globals.ListUint, 0)
	retry := true
	for retry {
		retry = false
		for _, group := range globals.ListGroups {
			if slices.Contains(groupProcessed, group.ID) {
				continue
			}
			if group.Level > contextGin.GetUint("violation_level") {
				continue
			}
			oldLevel := contextGin.GetUint("violation_level")
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
			actionConditions := make([]bool, 0)
			actionCallbacks := make([]actionCallback, 0)
			for _, rule := range rules {
				switch context.(type) {
				case *gin.Context:
					if !slices.Contains(globals.ListUint8{0, 1, 2}, rule.Phase) {
						continue
					}
				case *http.Response:
					if !slices.Contains(globals.ListUint8{3, 4, 5}, rule.Phase) {
						continue
					}
				}
				targetGetted := func() ([]globals.Target, any) {
					var (
						targetPath      []globals.Target
						targetProcessed any
					)
					target, ok := globals.Targets[rule.TargetID]
					if ok {
						if target.Immutable {
							targetPath = []globals.Target{target}
							targetProcessed = targets.ProcessImmutableTarget(context, &target)
						} else {
							targetPath, targetProcessed = targets.ProcessTarget(context, contextGin, target.ID)
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
				if result := comparators.Compare(targetValue, &rule); !result {
					actionConditions = append(actionConditions, result)
					continue
				} else {
					actionConditions = append(actionConditions, result)
				}
				if rule.Action == nil {
					continue
				}
				actionCallbacks = append(actionCallbacks, actionCallback{
					targetPath:  targetPath,
					targetValue: targetValue,
					rule:        &rule,
				})
			}
			if !slices.Contains(actionConditions, false) {
				for _, actionCallback := range actionCallbacks {
					forceReturn, result, audit := actions.Perform(
						context,
						contextGin,
						&group,
						actionCallback.targetPath,
						actionCallback.targetValue,
						actionCallback.rule,
					)
					if audit {
						logistic := logistics.NewLogistic(actionCallback.rule)
						if err := logistic.Write(
							context,
							actionCallback.targetValue,
							&actionCallback.targetPath,
							actionCallback.rule,
						); err != nil {
							msg := fmt.Sprintf("Rule %d: %v", actionCallback.rule.ID, err)
							errors.WriteErrorLogisticLog(msg)
						}
					}
					if forceReturn {
						return result
					}
				}
			}
			groupProcessed = append(groupProcessed, group.ID)
			if oldLevel != contextGin.GetUint("violation_level") {
				retry = true
				break
			}
		}
	}
	return contextGin.GetInt("current_score") < contextGin.GetInt("violation_score")
}
