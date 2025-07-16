package phase4

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"fmt"
	"io"
	"madsecurity-defender/globals"
	"madsecurity-defender/services/controllers/proxy/execute/errors"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func decodeResponseBody(context *http.Response) ([]byte, error) {
	var (
		reader io.ReadCloser
		err    error
	)
	switch context.Header.Get("Content-Encoding") {
	case "gzip":
		reader, err = gzip.NewReader(context.Body)
		if err != nil {
			return nil, err
		}
	case "deflate":
		reader = flate.NewReader(context.Body)
	case "br":
		reader = io.NopCloser(brotli.NewReader(context.Body))
	case "zstd":
		decoder, dErr := zstd.NewReader(context.Body)
		if dErr != nil {
			return nil, dErr
		}
		defer decoder.Close()
		return io.ReadAll(decoder)
	case "compress":
		reader = io.NopCloser(lzw.NewReader(context.Body, lzw.MSB, 8))
	default:
		reader = context.Body
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	context.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}

func extractApplicationJson(body string) {
	
}

func GetBodyData(context *http.Response, targetId uint) (globals.ListString, globals.ListString, globals.DictString) {
	keys := make(globals.ListString, 0)
	values := make(globals.ListString, 0)
	maps := make(globals.DictString, 0)
	contentType := context.Header.Get("Content-Type")
	if len(contentType) > 0 {
		mediaType, _, err := mime.ParseMediaType(contentType)
		if err != nil {
			msg := fmt.Sprintf("Target %d: %v", targetId, err)
			errors.WriteErrorTargetLog(msg)
		} else {
			formatRegex := regexp.MustCompile(`(?i)\b(json|xml|yaml)\b`)
			match := formatRegex.FindStringSubmatch(mediaType)
			if len(match) >= 2 {
				switch strings.ToLower(match[1]) {
				case "json":
				case "xml":
				case "yaml":
				}
			}
		}
	}
	return keys, values, maps
}
