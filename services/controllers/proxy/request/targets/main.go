package targets

import (
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/request/targets/phase0"
	"madsecurity-defender/services/controllers/proxy/request/targets/phase1"

	"github.com/gin-gonic/gin"
)

func Execute(context *gin.Context, phase uint8) {
	for _, group := range globals.ListGroups {
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
								return ProcessArrayTarget(context, &target)
							case "number":
								return ProcessNumberTarget(context, &target)
							case "string":
								return ProcessStringTarget(context, &target)
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
			if rule.Phase != phase {
				continue
			}
		}
	}
}