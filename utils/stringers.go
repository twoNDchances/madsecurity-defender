package utils

func ReplaceIfWhiteSpace(value, new string) string {
	if len(value) == 0 {
		return new
	}
	return value
}

func FallbackWhenEmpty(value, new *string) *string {
	if len(*value) != 0 {
		return value
	}
	return new
}
