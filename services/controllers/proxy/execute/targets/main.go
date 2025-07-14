package targets

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase0"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase1"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase2"
	"madsecurity-defender/utils"
	"strconv"

	"github.com/gin-gonic/gin"
)

func ProcessImmutableTarget(context *gin.Context, target *globals.Target) any {
	var targetGetted any
	switch target.Phase {
	case 0:
		if target.Alias == "full-request" {
			targetGetted = phase0.FullRequest(context, target)
		}
	case 1:
		switch target.Alias {
		case "header-keys":
			targetGetted = phase1.HeaderKeys(context, target)
		case "header-values":
			targetGetted = phase1.HeaderValues(context, target)
		case "url-args-keys":
			targetGetted = phase1.UrlArgsKeys(context, target)
		case "url-args-values":
			targetGetted = phase1.UrlArgsValues(context, target)
		case "header-size":
			targetGetted = phase1.HeaderSize(context, target)
		case "url-port":
			targetGetted = phase1.UrlPort(context, target)
		case "url-args-size":
			targetGetted = phase1.UrlArgsSize(context, target)
		case "client-ip":
			targetGetted = phase1.ClientIp(context, target)
		case "client-method":
			targetGetted = phase1.ClientMethod(context, target)
		case "url-path":
			targetGetted = phase1.UrlPath(context, target)
		case "url-scheme":
			targetGetted = phase1.UrlScheme(context, target)
		case "url-host":
			targetGetted = phase1.UrlHost(context, target)
		}
	case 2:
		switch target.Alias {
		case "body-keys":
			targetGetted = phase2.BodyKeys(context, target)
		case "file-keys":
			targetGetted = phase2.FileKeys(context, target)
		case "body-values":
			targetGetted = phase2.BodyValues(context, target)
		case "file-values":
			targetGetted = phase2.FileValues(context, target)
		case "file-names":
			targetGetted = phase2.FileNames(context, target)
		case "file-extensions":
			targetGetted = phase2.FileExtensions(context, target)
		case "body-size":
			targetGetted = phase2.BodySize(context, target)
		case "file-size":
			targetGetted = phase2.FileSize(context, target)
		case "file-name-size":
			targetGetted = phase2.FileNameSize(context, target)
		case "body-length":
			targetGetted = phase2.BodyLength(context, target)
		case "file-length":
			targetGetted = phase2.FileLength(context, target)
		case "body-full":
			targetGetted = phase2.FullBody(context, target)
		}
	case 3:
		switch target.Alias {
		}
	case 4:
		switch target.Alias {
		}
	case 5:
		if target.Alias == "full-response" {
		}
	}
	return targetGetted
}

func ProcessUnimmutableTarget(context *gin.Context, target *globals.Target) any {
	var targetProcessed any
	switch target.Datatype {
	case "array":
		targetProcessed = ProcessArrayTarget(context, target)
	case "number":
		targetProcessed = ProcessNumberTarget(context, target)
	case "string":
		targetProcessed = ProcessStringTarget(context, target)
	}
	return targetProcessed
}

func ProcessRefererTarget(context *gin.Context, targetId uint) ([]globals.Target, any) {
	targetPath := GetToRootTargets(context, targetId)
	var targetProcessed any
	if len(targetPath) == 0 {
		msg := fmt.Sprintf("Target %d: not found Target", targetId)
		errors.WriteErrorTargetLog(msg)
		return targetPath, targetProcessed
	}
	root := targetPath[0]
	if root.Immutable {
		targetProcessed = ProcessImmutableTarget(context, &root)
	} else {
		targetProcessed = ProcessUnimmutableTarget(context, &root)
	}
	if targetProcessed == nil {
		//
		return targetPath, targetProcessed
	}
	if len(targetPath[1:]) == 0 {
		return targetPath, targetProcessed
	}
	targetChains := targetPath[1:]
	for _, targetChain := range targetChains {
		if targetChain.Engine == nil {
			continue
		}
		if targetChain.EngineConfiguration != nil {
			switch t := targetProcessed.(type) {
			case globals.ListString:
				if targetChain.FinalDatatype == "array" {
				}
				if targetChain.FinalDatatype == "number" {
				}
				if targetChain.FinalDatatype == "string" {
					if *targetChain.Engine == "indexOf" {
						engineConfiguration, err := strconv.Atoi(*targetChain.EngineConfiguration)
						if err != nil {
							msg := fmt.Sprintf("Target %d: %v", targetId, err)
							errors.WriteErrorTargetLog(msg)
							engineConfiguration = 0
						}
						targetProcessed = IndexOf(&t, engineConfiguration)
					}
				}
			case float64:
				if targetChain.FinalDatatype == "array" {
				}
				if targetChain.FinalDatatype == "number" {
					engineConfiguration, err := utils.ToFloat64(*targetChain.EngineConfiguration)
					if err != nil {
						msg := fmt.Sprintf("Target %d: %v", targetId, err)
						errors.WriteErrorTargetLog(msg)
						engineConfiguration = 0
					}
					if *targetChain.Engine == "addition" {
						targetProcessed = Addition(t, engineConfiguration)
					}
					if *targetChain.Engine == "subtraction" {
						targetProcessed = Subtraction(t, engineConfiguration)
					}
					if *targetChain.Engine == "multiplication" {
						targetProcessed = Multiplication(t, engineConfiguration)
					}
					if *targetChain.Engine == "division" {
						targetProcessed = Division(t, engineConfiguration)
					}
					if *targetChain.Engine == "powerOf" {
						targetProcessed = PowerOf(t, engineConfiguration)
					}
					if *targetChain.Engine == "remainder" {
						targetProcessed = Remainder(t, engineConfiguration)
					}
				}
				if targetChain.FinalDatatype == "string" {
				}
			case string:
				if targetChain.FinalDatatype == "array" {
				}
				if targetChain.FinalDatatype == "number" {
				}
				if targetChain.FinalDatatype == "string" {
					if *targetChain.Engine == "hash" {
						targetProcessed = Hash(t, *targetChain.EngineConfiguration)
					}
				}
			}
		} else {
			switch t := targetProcessed.(type) {
			case globals.ListString:
				if targetChain.FinalDatatype == "array" {
				}
				if targetChain.FinalDatatype == "number" {
				}
				if targetChain.FinalDatatype == "string" {
				}
			case float64:
				if targetChain.FinalDatatype == "array" {
				}
				if targetChain.FinalDatatype == "number" {
				}
				if targetChain.FinalDatatype == "string" {
				}
			case string:
				if targetChain.FinalDatatype == "array" {
				}
				if targetChain.FinalDatatype == "number" {
					if *targetChain.Engine == "length" {
						targetProcessed = Length(t)
					}
				}
				if targetChain.FinalDatatype == "string" {
					if *targetChain.Engine == "lower" {
						targetProcessed = Lower(t)
					}
					if *targetChain.Engine == "upper" {
						targetProcessed = Upper(t)
					}
					if *targetChain.Engine == "capitalize" {
						targetProcessed = Capitalize(t)
					}
					if *targetChain.Engine == "trim" {
						targetProcessed = Trim(t)
					}
					if *targetChain.Engine == "trimLeft" {
						targetProcessed = TrimLeft(t)
					}
					if *targetChain.Engine == "trimRight" {
						targetProcessed = TrimRight(t)
					}
					if *targetChain.Engine == "removeWhitespace" {
						targetProcessed = RemoveWhitespace(t)
					}
				}
			}
		}
	}
	return targetPath, targetProcessed
}

func ProcessTarget(context *gin.Context, targetId uint) ([]globals.Target, any) {
	var targetPath []globals.Target
	target, ok := globals.Targets[targetId]
	if !ok {
		return targetPath, nil
	}
	var targetProcessed any
	if target.Immutable {
		targetPath = []globals.Target{target}
		targetProcessed = ProcessImmutableTarget(context, &target)
	} else {
		switch target.Type {
		case "getter", "header", "url.args", "body", "file":
			targetPath = []globals.Target{target}
			targetProcessed = ProcessUnimmutableTarget(context, &target)
		case "target":
			targetPath, targetProcessed = ProcessRefererTarget(context, targetId)
		}
	}
	return targetPath, targetProcessed
}
