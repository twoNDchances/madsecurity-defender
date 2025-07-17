package utils

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
)

func FlattenWithValues(data interface{}, prefix string, out map[string]interface{}) {
	switch v := data.(type) {
	case map[string]interface{}:
		for key, val := range v {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "." + key
			}
			FlattenWithValues(val, fullKey, out)
		}
	case []interface{}:
		for i, val := range v {
			idx := strconv.Itoa(i)
			fullKey := idx
			if prefix != "" {
				fullKey = prefix + "." + idx
			}
			FlattenWithValues(val, fullKey, out)
		}
	default:
		out[prefix] = v
	}
}

func DecodeResponseBody(context *http.Response) ([]byte, error) {
	encoding := strings.ToLower(context.Header.Get("Content-Encoding"))
	var (
		reader io.ReadCloser
		err    error
	)
	switch encoding {
	case "gzip":
		reader, err = gzip.NewReader(context.Body)
	case "deflate":
		reader = io.NopCloser(flate.NewReader(context.Body))
	case "zlib", "compress":
		reader, err = zlib.NewReader(context.Body)
	case "br":
		reader = io.NopCloser(brotli.NewReader(context.Body))
	case "zstd":
		zreader, err := zstd.NewReader(context.Body)
		if err != nil {
			return nil, err
		}
		defer zreader.Close()
		data, err := io.ReadAll(zreader)
		if err == nil {
			context.Body = io.NopCloser(bytes.NewReader(data))
		}
		return data, err
	default:
		reader = context.Body
	}
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	context.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}
