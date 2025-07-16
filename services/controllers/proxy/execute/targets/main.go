package targets

import (
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase0"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase1"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase2"
	"madsecurity-defender/services/controllers/proxy/execute/targets/phase3"
	"madsecurity-defender/utils"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func ProcessImmutableTarget(context any, target *globals.Target) any {
	var targetGetted any
	switch ctx := context.(type) {
	case *gin.Context:
		switch target.Phase {
		case 0:
			if target.Alias == "full-request" {
				targetGetted = phase0.FullRequest(ctx, target)
			}
		case 1:
			switch target.Alias {
			case "header-keys-request":
				targetGetted = phase1.HeaderKeys(ctx, target)
			case "header-values-request":
				targetGetted = phase1.HeaderValues(ctx, target)
			case "url-args-keys":
				targetGetted = phase1.UrlArgsKeys(ctx, target)
			case "url-args-values":
				targetGetted = phase1.UrlArgsValues(ctx, target)
			case "header-size-request":
				targetGetted = phase1.HeaderSize(ctx, target)
			case "url-port":
				targetGetted = phase1.UrlPort(ctx, target)
			case "url-args-size":
				targetGetted = phase1.UrlArgsSize(ctx, target)
			case "client-protocol":
				targetGetted = phase1.ClientProtocol(ctx, target)
			case "client-ip":
				targetGetted = phase1.ClientIp(ctx, target)
			case "client-method":
				targetGetted = phase1.ClientMethod(ctx, target)
			case "url-path":
				targetGetted = phase1.UrlPath(ctx, target)
			case "url-scheme":
				targetGetted = phase1.UrlScheme(ctx, target)
			case "url-host":
				targetGetted = phase1.UrlHost(ctx, target)
			case "full-header-request":
				targetGetted = phase1.FullHeader(ctx, target)
			}
		case 2:
			switch target.Alias {
			case "body-keys-request":
				targetGetted = phase2.BodyKeys(ctx, target)
			case "file-keys-request":
				targetGetted = phase2.FileKeys(ctx, target)
			case "body-values-request":
				targetGetted = phase2.BodyValues(ctx, target)
			case "file-values-request":
				targetGetted = phase2.FileValues(ctx, target)
			case "file-names-request":
				targetGetted = phase2.FileNames(ctx, target)
			case "file-extensions-request":
				targetGetted = phase2.FileExtensions(ctx, target)
			case "body-size-request":
				targetGetted = phase2.BodySize(ctx, target)
			case "file-size-request":
				targetGetted = phase2.FileSize(ctx, target)
			case "file-name-size-request":
				targetGetted = phase2.FileNameSize(ctx, target)
			case "body-length-request":
				targetGetted = phase2.BodyLength(ctx, target)
			case "file-length-request":
				targetGetted = phase2.FileLength(ctx, target)
			case "body-full-request":
				targetGetted = phase2.FullBody(ctx, target)
			}
		}
	case *http.Response:
		switch target.Phase {
		case 3:
			switch target.Alias {
			case "header-keys-response":
				targetGetted = phase3.HeaderKeys(ctx, target)
			case "header-values-response":
				targetGetted = phase3.HeaderValues(ctx, target)
			case "header-size-response":
				targetGetted = phase3.HeaderSize(ctx, target)
			case "server-status":
				targetGetted = phase3.ServerStatus(ctx, target)
			case "server-protocol":
				targetGetted = phase3.ServerProtocol(ctx, target)
			case "full-header-response":
				targetGetted = phase3.FullHeader(ctx, target)
			}
		case 4:
			switch target.Alias {
			}
		case 5:
			if target.Alias == "full-response" {
			}
		}
	}
	return targetGetted
}

func ProcessUnimmutableTarget(context any, contextGin *gin.Context, target *globals.Target) any {
	var targetProcessed any
	switch target.Datatype {
	case "array":
		targetProcessed = ProcessArrayTarget(context, target)
	case "number":
		targetProcessed = ProcessNumberTarget(context, target)
	case "string":
		targetProcessed = ProcessStringTarget(context, contextGin, target)
	}
	return targetProcessed
}

func ProcessRefererTarget(context any, contextGin *gin.Context, targetId uint) ([]globals.Target, any) {
	targetPath := GetToRootTargets(targetId)
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
		targetProcessed = ProcessUnimmutableTarget(context, contextGin, &root)
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

func ProcessTarget(context any, contextGin *gin.Context, targetId uint) ([]globals.Target, any) {
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
			targetProcessed = ProcessUnimmutableTarget(context, contextGin, &target)
		case "target":
			targetPath, targetProcessed = ProcessRefererTarget(context, contextGin, targetId)
		}
	}
	return targetPath, targetProcessed
}
