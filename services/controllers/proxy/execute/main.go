package execute

import (
	"errors"
	"fmt"
	"log"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/actions"
	perform "madsecurity-defender/services/controllers/proxy/execute/rules"
	"madsecurity-defender/services/controllers/proxy/execute/targets"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase0"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase1"
	"slices"
	"strconv"

	"github.com/gin-gonic/gin"
)

func Request(context *gin.Context, proxy *globals.Proxy) bool {
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
							targetPath := targets.GetToRootTargets(context, rule.TargetID)
							if len(targetPath) == 0 {
								msg := fmt.Sprintf("Target %d not found", rule.TargetID)
								context.Error(errors.New(msg))
								return nil
							}
							var targetProcessed any
							log.Println(targetPath)
							for _, targetFromRoot := range targetPath {
								eachTarget := func() any {
									if targetFromRoot.Immutable {
										switch targetFromRoot.Phase {
										case 0:
											if targetFromRoot.Alias == "full-request" {
												return phase0.FullRequest(context, &targetFromRoot)
											}
										case 1:
											switch targetFromRoot.Alias {
											case "header-keys":
												return phase1.HeaderKeys(context, &targetFromRoot)
											case "header-values":
												return phase1.HeaderValues(context, &targetFromRoot)
											case "url-args-keys":
												return phase1.UrlArgsKeys(context, &targetFromRoot)
											case "url-args-values":
												return phase1.UrlArgsValues(context, &targetFromRoot)
											case "header-size":
												return phase1.HeaderSize(context, &targetFromRoot)
											case "url-port":
												return phase1.UrlPort(context, &targetFromRoot)
											case "url-args-size":
												return phase1.UrlArgsSize(context, &targetFromRoot)
											case "client-ip":
												return phase1.ClientIp(context, &targetFromRoot)
											case "client-method":
												return phase1.ClientMethod(context, &targetFromRoot)
											case "url-path":
												return phase1.UrlPath(context, &targetFromRoot)
											case "url-scheme":
												return phase1.UrlScheme(context, &targetFromRoot)
											case "url-host":
												return phase1.UrlHost(context, &targetFromRoot)
											default:
												return nil
											}
										case 2:
										case 3:
										case 4:
										case 5:
										}
									} else {
										if slices.Contains(globals.ListString{
											"header",
											"url.args",
										}, targetFromRoot.Datatype) {
											switch targetFromRoot.Datatype {
											case "array":
												return targets.GetArrayTarget(context, &targetFromRoot)
											case "number":
												return targets.GetNumberTarget(context, &targetFromRoot)
											case "string":
												return targets.GetStringTarget(context, &targetFromRoot)
											}
										} else {
											//
										}
									}
									return nil
								}
								targetGetted := eachTarget()
								log.Println(targetGetted)
								if targetFromRoot.Engine != nil {
									if targetFromRoot.EngineConfiguration != nil {
										switch t := targetGetted.(type) {
										case globals.ListString:
											if targetFromRoot.FinalDatatype == "array" {}
											if targetFromRoot.FinalDatatype == "number" {}
											if targetFromRoot.FinalDatatype == "string" {
												if *targetFromRoot.Engine == "indexOf" {
													engineConfiguration, err := strconv.Atoi(*targetFromRoot.EngineConfiguration)
													if err != nil {
														context.Error(err)
														engineConfiguration = 0
													}
													if targetProcessed == nil {
														targetProcessed = targets.IndexOf(&t, engineConfiguration)
													} else {
														targetProcessed = targets.IndexOf(targetProcessed.(*globals.ListString), engineConfiguration)
													}
												}
											}
										case float64:
											if targetFromRoot.FinalDatatype == "array" {}
											if targetFromRoot.FinalDatatype == "number" {
												engineConfiguration, err := strconv.ParseFloat(*targetFromRoot.EngineConfiguration, 64)
												if err != nil {
													context.Error(err)
													engineConfiguration = 0
												}
												if *targetFromRoot.Engine == "addition" {
													if targetProcessed == nil {
														targetProcessed = targets.Addition(t, engineConfiguration)
													} else {
														targetProcessed = targets.Addition(targetProcessed.(float64), engineConfiguration)
													}
												}
												if *targetFromRoot.Engine == "subtraction" {
													if targetProcessed == nil {
														targetProcessed = targets.Subtraction(t, engineConfiguration)
													} else {
														targetProcessed = targets.Subtraction(targetProcessed.(float64), engineConfiguration)
													}
												}
												if *targetFromRoot.Engine == "multiplication" {
													if targetProcessed == nil {
														targetProcessed = targets.Multiplication(t, engineConfiguration)
													} else {
														targetProcessed = targets.Multiplication(targetProcessed.(float64), engineConfiguration)
													}
												}
												if *targetFromRoot.Engine == "division" {
													if targetProcessed == nil {
														targetProcessed = targets.Division(t, engineConfiguration)
													} else {
														targetProcessed = targets.Division(targetProcessed.(float64), engineConfiguration)
													}
												}
												if *targetFromRoot.Engine == "powerOf" {
													if targetProcessed == nil {
														targetProcessed = targets.PowerOf(t, engineConfiguration)
													} else {
														targetProcessed = targets.PowerOf(targetProcessed.(float64), engineConfiguration)
													}
												}
												if *targetFromRoot.Engine == "remainder" {
													if targetProcessed == nil {
														targetProcessed = targets.Remainder(t, engineConfiguration)
													} else {
														targetProcessed = targets.PowerOf(targetProcessed.(float64), engineConfiguration)
													}
												}
											}
											if targetFromRoot.FinalDatatype == "string" {}
										case string:
											if targetFromRoot.FinalDatatype == "array" {}
											if targetFromRoot.FinalDatatype == "number" {}
											if targetFromRoot.FinalDatatype == "string" {
												if *targetFromRoot.Engine == "hash" {
													if targetProcessed == nil {
														targetProcessed = targets.Hash(t, *targetFromRoot.EngineConfiguration)
													} else {
														targetProcessed = targets.Hash(targetProcessed.(string), *targetFromRoot.EngineConfiguration)
													}
												}
											}
										}
									} else {
										switch t := targetGetted.(type) {
										case globals.ListString:
											if targetFromRoot.FinalDatatype == "array" {}
											if targetFromRoot.FinalDatatype == "number" {}
											if targetFromRoot.FinalDatatype == "string" {}
										case float64:
											if targetFromRoot.FinalDatatype == "array" {}
											if targetFromRoot.FinalDatatype == "number" {}
											if targetFromRoot.FinalDatatype == "string" {}
										case string:
											if targetFromRoot.FinalDatatype == "array" {}
											if targetFromRoot.FinalDatatype == "number" {
												if *targetFromRoot.Engine == "length" {
													if targetProcessed == nil {
														targetProcessed = targets.Length(t)
													} else {
														targetProcessed = targets.Length(targetProcessed.(string))
													}
												}
											}
											if targetFromRoot.FinalDatatype == "string" {
												if *targetFromRoot.Engine == "lower" {
													if targetProcessed == nil {
														targetProcessed = targets.Lower(t)
													} else {
														targetProcessed = targets.Lower(targetProcessed.(string))
													}
												}
												if *targetFromRoot.Engine == "upper" {
													if targetProcessed == nil {
														targetProcessed = targets.Upper(t)
													} else {
														targetProcessed = targets.Upper(targetProcessed.(string))
													}
												}
												if *targetFromRoot.Engine == "capitalize" {
													if targetProcessed == nil {
														targetProcessed = targets.Capitalize(t)
													} else {
														targetProcessed = targets.Capitalize(targetProcessed.(string))
													}
												}
												if *targetFromRoot.Engine == "trim" {
													if targetProcessed == nil {
														targetProcessed = targets.Trim(t)
													} else {
														targetProcessed = targets.Trim(targetProcessed.(string))
													}
												}
												if *targetFromRoot.Engine == "trimLeft" {
													if targetProcessed == nil {
														targetProcessed = targets.TrimLeft(t)
													} else {
														targetProcessed = targets.TrimLeft(targetProcessed.(string))
													}
												}
												if *targetFromRoot.Engine == "trimRight" {
													if targetProcessed == nil {
														targetProcessed = targets.TrimRight(t)
													} else {
														targetProcessed = targets.TrimRight(targetProcessed.(string))
													}
												}
												if *targetFromRoot.Engine == "removeWhitespace" {
													if targetProcessed == nil {
														targetProcessed = targets.RemoveWhitespace(t)
													} else {
														targetProcessed = targets.RemoveWhitespace(targetProcessed.(string))
													}
												}
											}
										}
									}
								}
							}
							return targetProcessed
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
			if !slices.Contains(globals.ListUint8{0,1,2}, rule.Phase) {
				continue
			}
			if perform.CheckRule(context, target, &rule) {
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
	}
	return scoreDefault < score
}

func Response() {
	//
}
