package utils

import (
	"fmt"
	"strconv"
)

func ToBoolean(value string) (bool, error) {
	return strconv.ParseBool(value)
}

func ToUint(value string) (uint32, error) {
	number, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, err
	}
	if number > uint64(^uint32(0)) {
		return 0, fmt.Errorf("value exceeds the limit of uint32")
	}
	return uint32(number), nil
}
