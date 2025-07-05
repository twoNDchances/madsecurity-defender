package targets

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"madsecurity-defender/utils"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/gin-gonic/gin"
)

func IndexOf(targets *globals.ListString, index int) string {
	if len(*targets) == 0 {
		return ""
	}
	if index < 0 {
		return (*targets)[0]
	}
	if index >= len(*targets) {
		return (*targets)[len(*targets)-1]
	}
	return (*targets)[index]
}

func ProcessArrayTarget(context *gin.Context, target *globals.Target) any {
	targetValue := GetArrayTarget(context, target)
	if target.Engine != nil {
		if target.EngineConfiguration != nil {
			if target.FinalDatatype == "array" {
			}
			if target.FinalDatatype == "number" {
			}
			if target.FinalDatatype == "string" {
				if *target.Engine == "indexOf" {
					engineConfiguration, err := strconv.Atoi(*target.EngineConfiguration)
					if err != nil {
						msg := fmt.Sprintf("Target %d: %v", target.ID, err)
						errors.WriteErrorEngineLog(msg)
						engineConfiguration = 0
					}
					return IndexOf(&targetValue, engineConfiguration)
				}
			}
		} else {
			if target.FinalDatatype == "array" {
			}
			if target.FinalDatatype == "number" {
			}
			if target.FinalDatatype == "string" {
			}
		}
	}
	return targetValue
}

func Addition(target float64, number float64) float64 {
	return target + number
}

func Subtraction(target float64, number float64) float64 {
	return target - number
}

func Multiplication(target float64, number float64) float64 {
	return target * number
}

func Division(target float64, number float64) float64 {
	return target / number
}

func PowerOf(target float64, number float64) float64 {
	return math.Pow(target, number)
}

func Remainder(target float64, number float64) float64 {
	return math.Mod(target, number)
}

func ProcessNumberTarget(context *gin.Context, target *globals.Target) any {
	targetValue := GetNumberTarget(context, target)
	if target.Engine != nil {
		if target.EngineConfiguration != nil {
			if target.FinalDatatype == "array" {
			}
			if target.FinalDatatype == "number" {
				engineConfiguration, err := utils.ToFloat64(*target.EngineConfiguration)
				if err != nil {
					msg := fmt.Sprintf("Target %d: %v", target.ID, err)
					errors.WriteErrorEngineLog(msg)
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
			if target.FinalDatatype == "string" {
			}
		} else {
			if target.FinalDatatype == "array" {
			}
			if target.FinalDatatype == "number" {
			}
			if target.FinalDatatype == "string" {
			}
		}
	}
	return targetValue
}

func Lower(target string) string {
	return strings.ToLower(target)
}

func Upper(target string) string {
	return strings.ToUpper(target)
}

func Capitalize(target string) string {
	if len(target) == 0 {
		return target
	}
	return strings.ToUpper(target[:1]) + target[1:]
}

func Trim(target string) string {
	return strings.TrimSpace(target)
}

func TrimLeft(target string) string {
	return strings.TrimLeftFunc(target, unicode.IsSpace)
}

func TrimRight(target string) string {
	return strings.TrimRightFunc(target, unicode.IsSpace)
}

func RemoveWhitespace(target string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return r
	}, target)
}

func Length(target string) float64 {
	return float64(len(target))
}

func Hash(target string, algorithm string) string {
	if slices.Contains(globals.ListString{"md5", "sha128", "sha256", "sha512"}, algorithm) {
		switch algorithm {
		case "md5":
			hash := md5.Sum([]byte(target))
			return hex.EncodeToString(hash[:])
		case "sha128":
			hash := sha1.Sum([]byte(target))
			return hex.EncodeToString(hash[:])
		case "sha256":
			hash := sha256.Sum256([]byte(target))
			return hex.EncodeToString(hash[:])
		case "sha512":
			hash := sha512.Sum512([]byte(target))
			return hex.EncodeToString(hash[:])
		}
	}
	return ""
}

func ProcessStringTarget(context *gin.Context, target *globals.Target) any {
	targetValue := GetStringTarget(context, target)
	if target.Engine != nil {
		if target.EngineConfiguration != nil {
			if target.FinalDatatype == "array" {
			}
			if target.FinalDatatype == "number" {
			}
			if target.FinalDatatype == "string" {
				if *target.Engine == "hash" {
					return Hash(targetValue, *target.EngineConfiguration)
				}
			}
		} else {
			if target.FinalDatatype == "array" {
			}
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
	return targetValue
}
