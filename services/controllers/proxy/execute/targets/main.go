package targets

import (
	"madsecurity-defender/globals"
	"slices"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func getValueFromPhase1Type(context *gin.Context, target *globals.Target) globals.DictString {
	raw := make(map[string][]string, 0)
	if target.Type == "header" {
		raw = context.Request.Header
	}
	if target.Type == "url.args" {
		raw = context.Request.URL.Query()
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

func GetToRootTargets(context *gin.Context, targetId uint) []globals.Target {
	visited := make(map[uint]bool)
	path := make([]globals.Target, 0)
	currentId := targetId
	for {
		node, exists := globals.Targets[currentId]
		if !exists {
			break
		}
		path = append(path, node)
		if visited[currentId] {
			break
		}
		visited[currentId] = true
		if node.TargetID == nil {
			break
		}
		nextId := *node.TargetID
		if nextId == currentId {
			break
		}
		if visited[nextId] {
			break
		}
		if _, ok := globals.Targets[nextId]; !ok {
			break
		}
		currentId = nextId
	}
	slices.Reverse(path)
	return path
}
