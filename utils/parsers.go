package utils

import (
	"fmt"
	"strconv"
)

func ToBoolean(value string) (bool, error) {
	return strconv.ParseBool(value)
}

func ToInt(value string) (int, error) {
	number, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	if number > 4294967296 {
		return 0, fmt.Errorf("value exceeds the limit of int32")
	}
	return number, nil
}
