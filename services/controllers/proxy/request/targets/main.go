package targets

import (
	"madsecurity-defender/globals"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func findTargetByID(id uint) *globals.Target {
    for i := range globals.Targets {
        if globals.Targets[i].ID == id {
            // return &globals.Targets[i]
        }
    }
    return nil
}

func recursiveTarget(target *globals.Target) *globals.Target {
	visited := make(map[int]bool, 0)
    current := target
	for current != nil {
        if visited[int(current.ID)] {
            return current
        }
        visited[int(current.ID)] = true
        if current.TargetID == nil {
            return current
        }
        next := findTargetByID(*current.TargetID)
		if next == nil {
			return current
		}
		current = next
    }
	return nil
}

func getValueFromPhase1Type(context *gin.Context, target *globals.Target) globals.DictString {
	raw := make(map[string][]string, 0)
	if target.Type == "header" {
		raw = context.Request.Header
	}
	if target.Type == "url.args" {
		raw = context.Request.URL.Query()
	}
	if target.Type == "target" {
		if target.TargetID != nil {
			get := recursiveTarget(target)
			return getValueFromPhase1Type(context, get)
		}
	}
	values := make(globals.DictString, 0)
	for key, value := range raw {
		values[strings.ToLower(key)] = strings.Join(value, ",")
	}
	return values
}

func GetArrayTarget(context *gin.Context, target *globals.Target) globals.ListString {
	var needed globals.ListString
	if target.Phase == 1 && target.Datatype == "array" && target.WordlistID != nil {
		words := make(globals.ListString, 0)
		for _, word := range globals.Words {
			if word.WordlistID == *target.WordlistID {
				words = append(words, word.Content)
			}
		}
		values := getValueFromPhase1Type(context, target)
		for _, word := range words {
			if value, ok := values[word]; ok {
				needed = append(needed, value)
			}
		}
	}
	return needed
}

func GetNumberTarget(context *gin.Context, target *globals.Target) float64 {
	var needed float64
	if target.Phase == 1 && target.Datatype == "number" {
		values := getValueFromPhase1Type(context, target)
		if value, ok := values[target.Name]; ok {
			number, err := strconv.ParseFloat(value, 64)
			if err != nil {
				context.Error(err)
			} else {
				needed = number
			}
		}
	}
	return needed
}

func GetStringTarget(context *gin.Context, target *globals.Target) string {
	var needed string
	if target.Phase == 1 && target.Datatype == "string" {
		values := getValueFromPhase1Type(context, target)
		if value, ok := values[target.Name]; ok {
			needed = value 
		}
	}
	return needed
}

func ProcessTarget(context *gin.Context, target *globals.Target) any {
	switch target.Datatype {
	case "array":
		targetValue := GetArrayTarget(context, target)
		if target.EngineConfiguration != nil {
			if target.FinalDatatype == "array" {}
			if target.FinalDatatype == "number" {}
			if target.FinalDatatype == "string" {
				if *target.Engine == "indexOf" {
					engineConfiguration, err := strconv.Atoi(*target.EngineConfiguration)
					if err != nil {
						context.Error(err)
						engineConfiguration = 0
					}
					return IndexOf(&targetValue, engineConfiguration)
				}
			}
		} else {
			if target.FinalDatatype == "array" {}
			if target.FinalDatatype == "number" {}
			if target.FinalDatatype == "string" {}
		}
		return targetValue
	case "number":
		targetValue := GetNumberTarget(context, target)
		if target.EngineConfiguration != nil {
			if target.FinalDatatype == "array" {}
			if target.FinalDatatype == "number" {
				engineConfiguration, err := strconv.ParseFloat(*target.EngineConfiguration, 64)
				if err != nil {
					context.Error(err)
					engineConfiguration = 0
				}
				if *target.Engine == "addition" {
					return Addition(targetValue, engineConfiguration)
				}
				if *target.Engine == "subtraction" {
					return Subtraction(targetValue, engineConfiguration)
				}
				if *target.Engine == "multiplication" {
					return Multiplication(targetValue, engineConfiguration)
				}
				if *target.Engine == "division" {
					return Division(targetValue, engineConfiguration)
				}
				if *target.Engine == "powerOf" {
					return PowerOf(targetValue, engineConfiguration)
				}
				if *target.Engine == "remainder" {
					return Remainder(targetValue, engineConfiguration)
				}
			}
			if target.FinalDatatype == "string" {}
		} else {
			if target.FinalDatatype == "array" {}
			if target.FinalDatatype == "number" {}
			if target.FinalDatatype == "string" {}
		}
		return targetValue
	case "string":
		targetValue := GetStringTarget(context, target)
		if target.EngineConfiguration != nil {
			if target.FinalDatatype == "array" {}
			if target.FinalDatatype == "number" {}
			if target.FinalDatatype == "string" {
				if *target.Engine == "hash" {
					return Hash(targetValue, *target.EngineConfiguration)
				}
			}
		} else {
			if target.FinalDatatype == "array" {}
			if target.FinalDatatype == "number" {
				if *target.Engine == "length" {
					return Length(targetValue)
				}
			}
			if target.FinalDatatype == "string" {
				if *target.Engine == "lower" {
					return Lower(targetValue)
				}
				if *target.Engine == "upper" {
					return Upper(targetValue)
				}
				if *target.Engine == "capitalize" {
					return Capitalize(targetValue)
				}
				if *target.Engine == "trim" {
					return Trim(targetValue)
				}
				if *target.Engine == "trimLeft" {
					return TrimLeft(targetValue)
				}
				if *target.Engine == "trimRight" {
					return TrimRight(targetValue)
				}
				if *target.Engine == "removeWhitespace" {
					return RemoveWhitespace(targetValue)
				}
			}
		}
	}
	return nil
}
