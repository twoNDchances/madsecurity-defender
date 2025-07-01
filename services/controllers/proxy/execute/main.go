package execute

import (
	"fmt"
	"madsecurity-defender/globals"
	perform "madsecurity-defender/services/controllers/proxy/execute/rules"
	"madsecurity-defender/services/controllers/proxy/execute/targets"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase0"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase1"
	"strconv"

	"github.com/gin-gonic/gin"
)

func Request(context *gin.Context, phase uint8, proxy *globals.Proxy) bool {
	level := globals.ViolationLevel
	score := globals.ViolationScore
	var scoreDefault int
	var breakSign bool
	for _, group := range globals.ListGroups {
		if breakSign {
			break
		}
		if group.Level != uint(level) {
			continue
		}
		getRules := func() []globals.Rule {
			rules := make([]globals.Rule, 0)
			for _, ruleId := range group.Rules {
				if rule, ok := globals.Rules[ruleId]; ok {
					rules = append(rules, rule)
				}
			}
			return rules
		}
		rules := getRules()
		for _, rule := range rules {
			getTarget := func() any {
				target, ok := globals.Targets[rule.TargetID]
				if !ok {
					return nil
				}
				if target.Immutable {
					switch target.Phase {
					case 0:
						if target.Alias == "full-request" {
							return phase0.FullRequest(context, &target)
						}
					case 1:
						switch target.Alias {
						case "header-keys":
							return phase1.HeaderKeys(context, &target)
						case "header-values":
							return phase1.HeaderValues(context, &target)
						case "url-args-keys":
							return phase1.UrlArgsKeys(context, &target)
						case "url-args-values":
							return phase1.UrlArgsValues(context, &target)
						case "header-size":
							return phase1.HeaderSize(context, &target)
						case "url-port":
							return phase1.UrlPort(context, &target)
						case "url-args-size":
							return phase1.UrlArgsSize(context, &target)
						case "client-ip":
							return phase1.ClientIp(context, &target)
						case "client-method":
							return phase1.ClientMethod(context, &target)
						case "url-path":
							return phase1.UrlPath(context, &target)
						case "url-scheme":
							return phase1.UrlScheme(context, &target)
						case "url-host":
							return phase1.UrlHost(context, &target)
						default:
							return nil
						}
					case 2:
					case 3:
					case 4:
					case 5:
					}
				} else {
					switch target.Phase {
					case 1:
						switch target.Type {
						case "header", "url.args":
							switch target.Datatype {
							case "array":
								return targets.ProcessArrayTarget(context, &target)
							case "number":
								return targets.ProcessNumberTarget(context, &target)
							case "string":
								return targets.ProcessStringTarget(context, &target)
							}
						case "target":

						}
					case 2:
					case 3:
					case 4:
					}
				}
				return nil
			}
			target := getTarget()
			if target == nil {
				context.Error(fmt.Errorf("target %d: unobtainable Target", rule.TargetID))
				continue
			}
			if rule.Phase != phase {
				continue
			}
			if perform.CheckRule(context, target, &rule) {
				if rule.Action == nil {
					continue
				}
				switch *rule.Action {
				case "allow":
					return true
				case "deny":
					return false
				case "inspect":
					if rule.Severity == nil {
						context.Error(fmt.Errorf("rule %d: missing Severity for Inspect action", rule.ID))
						return false
					}
					switch *rule.Severity {
					case "notice":
						scoreDefault = scoreDefault + proxy.Severity.NOTICE
					case "warning":
						scoreDefault = scoreDefault + proxy.Severity.WARNING
					case "error":
						scoreDefault = scoreDefault + proxy.Severity.ERROR
					case "critical":
						scoreDefault = scoreDefault + proxy.Severity.CRITICAL
					}
				case "request":
				case "setScore":
					if rule.ActionConfiguration == nil {
						context.Error(fmt.Errorf("rule %d: missing Action Configuration for Set Score action", rule.ID))
						return false
					}
					actionConfiguration, err := strconv.Atoi(*rule.ActionConfiguration)
					if err != nil {
						context.Error(fmt.Errorf("rule %d: %v", rule.ID, err))
						return false
					}
					score = actionConfiguration
				case "setLevel":
				case "report":
				}
			}
		}
	}
	return scoreDefault < score
}

func Response() {
	//
}
