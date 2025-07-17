package utils

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/lzw"
	"io"
	"net/http"
	"strconv"

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
			fullKey := prefix + "." + strconv.Itoa(i)
			FlattenWithValues(val, fullKey, out)
		}
	default:
		out[prefix] = v
	}
}

func DecodeResponseBody(context *http.Response) ([]byte, error) {
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
	defer reader.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	context.Body = io.NopCloser(bytes.NewReader(data))
	return data, nil
}
