package execute

import (
	"errors"
	"fmt"
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
				if !ok {
					return targetProcessed
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
							var targetGetted any
							if len(targetPath) > 0 {
								root := targetPath[0]
								if root.Immutable {
									switch root.Phase {
									case 0:
										if root.Alias == "full-request" {
											targetGetted = phase0.FullRequest(context, &root)
										}
									case 1:
										switch root.Alias {
										case "header-keys":
											targetGetted = phase1.HeaderKeys(context, &root)
										case "header-values":
											targetGetted = phase1.HeaderValues(context, &root)
										case "url-args-keys":
											targetGetted = phase1.UrlArgsKeys(context, &root)
										case "url-args-values":
											targetGetted = phase1.UrlArgsValues(context, &root)
										case "header-size":
											targetGetted = phase1.HeaderSize(context, &root)
										case "url-port":
											targetGetted = phase1.UrlPort(context, &root)
										case "url-args-size":
											targetGetted = phase1.UrlArgsSize(context, &root)
										case "client-ip":
											targetGetted = phase1.ClientIp(context, &root)
										case "client-method":
											targetGetted = phase1.ClientMethod(context, &root)
										case "url-path":
											targetGetted = phase1.UrlPath(context, &root)
										case "url-scheme":
											targetGetted = phase1.UrlScheme(context, &root)
										case "url-host":
											targetGetted = phase1.UrlHost(context, &root)
										}
									case 2:
									case 3:
									case 4:
									case 5:
									}
								} else {
									switch root.Datatype {
									case "array":
										targetGetted = targets.ProcessArrayTarget(context, &root)
									case "number":
										targetGetted = targets.ProcessNumberTarget(context, &root)
									case "string":
										targetGetted = targets.ProcessStringTarget(context, &root)
									}
								}
								if targetGetted == nil {
									//
									return nil
								}
								if len(targetPath[1:]) == 0 {
									return targetGetted
								}
								targetChains := targetPath[1:]
								for _, targetChain := range targetChains {
									if targetChain.Engine != nil {
										if targetChain.EngineConfiguration != nil {
											switch t := targetGetted.(type) {
											case globals.ListString:
												if targetChain.FinalDatatype == "array" {}
												if targetChain.FinalDatatype == "number" {}
												if targetChain.FinalDatatype == "string" {
													if *targetChain.Engine == "indexOf" {
														engineConfiguration, err := strconv.Atoi(*targetChain.EngineConfiguration)
														if err != nil {
															context.Error(err)
															engineConfiguration = 0
														}
														targetGetted = targets.IndexOf(&t, engineConfiguration)
													}
												}
											case float64:
												if targetChain.FinalDatatype == "array" {}
												if targetChain.FinalDatatype == "number" {
													engineConfiguration, err := strconv.ParseFloat(*targetChain.EngineConfiguration, 64)
													if err != nil {
														context.Error(err)
														engineConfiguration = 0
													}
													if *targetChain.Engine == "addition" {
														targetGetted = targets.Addition(t, engineConfiguration)
													}
													if *targetChain.Engine == "subtraction" {
														targetGetted = targets.Subtraction(t, engineConfiguration)
													}
													if *targetChain.Engine == "multiplication" {
														targetGetted = targets.Multiplication(t, engineConfiguration)
													}
													if *targetChain.Engine == "division" {
														targetGetted = targets.Division(t, engineConfiguration)
													}
													if *targetChain.Engine == "powerOf" {
														targetGetted = targets.PowerOf(t, engineConfiguration)
													}
													if *targetChain.Engine == "remainder" {
														targetGetted = targets.Remainder(t, engineConfiguration)
													}
												}
												if targetChain.FinalDatatype == "string" {}
											case string:
												if targetChain.FinalDatatype == "array" {}
												if targetChain.FinalDatatype == "number" {}
												if targetChain.FinalDatatype == "string" {
													if *targetChain.Engine == "hash" {
														targetGetted = targets.Hash(t, *targetChain.EngineConfiguration)
													}
												}
											}
										} else {
											switch t := targetGetted.(type) {
											case globals.ListString:
												if targetChain.FinalDatatype == "array" {}
												if targetChain.FinalDatatype == "number" {}
												if targetChain.FinalDatatype == "string" {}
											case float64:
												if targetChain.FinalDatatype == "array" {}
												if targetChain.FinalDatatype == "number" {}
												if targetChain.FinalDatatype == "string" {}
											case string:
												if targetChain.FinalDatatype == "array" {}
												if targetChain.FinalDatatype == "number" {
													if *targetChain.Engine == "length" {
														targetGetted = targets.Length(t)
													}
												}
												if targetChain.FinalDatatype == "string" {
													if *targetChain.Engine == "lower" {
														targetGetted = targets.Lower(t)
													}
													if *targetChain.Engine == "upper" {
														targetGetted = targets.Upper(t)
													}
													if *targetChain.Engine == "capitalize" {
														targetGetted = targets.Capitalize(t)
													}
													if *targetChain.Engine == "trim" {
														targetGetted = targets.Trim(t)
													}
													if *targetChain.Engine == "trimLeft" {
														targetGetted = targets.TrimLeft(t)
													}
													if *targetChain.Engine == "trimRight" {
														targetGetted = targets.TrimRight(t)
													}
													if *targetChain.Engine == "removeWhitespace" {
														targetGetted = targets.RemoveWhitespace(t)
													}
												}
											}
										}
									}
								}
							}
							return targetGetted
						}
					case 2:
					case 3:
					case 4:
					}
				}
				return nil
			}
			target := targetGetted()
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
