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
            return &globals.Targets[i]
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

func GetValueFromPhase1Type(context *gin.Context, target *globals.Target) globals.DictString {
	raw := make(map[string][]string, 0)
	if target.Type == "header" {
		raw = context.Request.Header
	}
	if target.Type == "array" {
		raw = context.Request.URL.Query()
	}
	if target.Type == "target" {
		if target.TargetID != nil {
			get := recursiveTarget(target)
			return GetValueFromPhase1Type(context, get)
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
	if target.Phase == 1 && target.Datatype == "array" && target.TargetID == nil && target.WordlistID != nil {
		words := make(globals.ListString, 0)
		for _, word := range globals.Words {
			if word.WordlistID == *target.WordlistID {
				words = append(words, word.Content)
			}
		}
		values := GetValueFromPhase1Type(context, target)
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
	if target.Phase == 1 && target.Datatype == "number" && target.TargetID == nil {
		values := GetValueFromPhase1Type(context, target)
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
	if target.Phase == 1 && target.Datatype == "string" && target.TargetID == nil {
		values := GetValueFromPhase1Type(context, target)
		if value, ok := values[target.Name]; ok {
			needed = value 
		}
	}
	return needed
}

// func GetNumberTargetUrlArg() float64 {
// 	var 
// }
