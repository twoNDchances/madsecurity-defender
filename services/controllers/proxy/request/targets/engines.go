package targets

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"madsecurity-defender/globals"
	"math"
	"slices"
	"strings"
	"unicode"
)

func IndexOf(targets *globals.ListString, index int) string {
	if len(*targets) == 0 {
        return ""
    }
    if index < 0 {
        return (*targets)[0]
    }
    if index >= len(*targets) {
        return (*targets)[len(*targets) - 1]
    }
    return (*targets)[index]
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
