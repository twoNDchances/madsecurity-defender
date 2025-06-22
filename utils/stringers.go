package utils

func ReplaceIfWhiteSpace(value, new string) string {
	if len(value) == 0 {
		return new
	}
	return value
}
